#include "update_database.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <curl/curl.h>

#define DATABASE_DIR      "database"
#define MAIN_URL          "https://database.clamav.net/main.cvd"
#define DAILY_URL         "https://database.clamav.net/daily.cvd"
#define SIX_WEEKS_SECONDS (6 * 7 * 24 * 60 * 60)

#define SYSTEM_CLAMAV_DIR "/var/lib/clamav"
#define SYSTEM_MAIN_CVD   SYSTEM_CLAMAV_DIR "/main.cvd"
#define SYSTEM_DAILY_CVD  SYSTEM_CLAMAV_DIR "/daily.cvd"

#define CVD_HEADER_SIZE 512

/* Path buffer size that is large enough for any path we build. */
#define PATHBUF 1400

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static int ensure_directory_exists(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "[!] '%s' exists and is not a directory\n", path);
        return -1;
    }
    if (mkdir(path, 0755) != 0) {
        perror("[!] Failed to create directory");
        return -1;
    }
    return 0;
}

static int file_is_nonempty(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode) && st.st_size > 0;
}

static int file_is_readable(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

static int file_is_stale(const char *path, time_t max_age) {
    struct stat st;
    if (stat(path, &st) != 0) return 1;
    return difftime(time(NULL), st.st_mtime) > max_age;
}

/* ------------------------------------------------------------------ */
/* HTTP download                                                      */
/* ------------------------------------------------------------------ */

static int download_file(const char *url, const char *out_path) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    FILE *fp = fopen(out_path, "wb");
    if (!fp) { curl_easy_cleanup(curl); return -1; }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: */*");
    headers = curl_slist_append(headers, "Connection: keep-alive");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 8L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 600L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
        "ClamAV/1.4.3 (OS: linux-gnu, ARCH: x86_64)");

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    fclose(fp);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        if (http_code == 429) {
            fprintf(stderr,
                "[~] CDN rate limit hit (HTTP 429). ClamAV allows only a "
                "few downloads per hour per IP.\n"
                "[~] Wait ~1 hour before retrying, or install ClamAV:\n"
                "[~]     sudo apt install -y clamav clamav-freshclam\n");
        } else {
            fprintf(stderr, "[~] Download failed (%s): %s (HTTP %ld)\n",
                    url, curl_easy_strerror(res), http_code);
        }
        unlink(out_path);
        return -1;
    }

    if (!file_is_nonempty(out_path)) {
        fprintf(stderr, "[~] Download produced empty file: %s\n", out_path);
        unlink(out_path);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* freshclam                                                          */
/* ------------------------------------------------------------------ */

static int run_freshclam(const char *dest_dir) {
    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
        }
        execlp("freshclam", "freshclam",
               "--quiet", "--datadir", dest_dir, (char *)NULL);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status)) return -1;
    return (WEXITSTATUS(status) == 0) ? 0 : -1;
}

static int copy_one_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }

    char buf[65536];
    size_t n;
    int ok = 1;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { ok = 0; break; }
    }
    if (ferror(in)) ok = 0;
    fclose(in);
    if (fclose(out) != 0) ok = 0;
    if (!ok) unlink(dst);
    return ok ? 0 : -1;
}

static int copy_from_dir(const char *src_dir,
                         const char *dst_main, const char *dst_daily) {
    const char *main_names[]  = { "main.cvd", "main.cld", NULL };
    const char *daily_names[] = { "daily.cvd", "daily.cld", NULL };

    char src_path[PATHBUF];
    int have_main = 0, have_daily = 0;

    for (int i = 0; main_names[i]; i++) {
        snprintf(src_path, sizeof(src_path), "%s/%s", src_dir, main_names[i]);
        if (file_is_nonempty(src_path)) {
            if (rename(src_path, dst_main) == 0 ||
                copy_one_file(src_path, dst_main) == 0) {
                have_main = 1; break;
            }
        }
    }
    for (int i = 0; daily_names[i]; i++) {
        snprintf(src_path, sizeof(src_path), "%s/%s", src_dir, daily_names[i]);
        if (file_is_nonempty(src_path)) {
            if (rename(src_path, dst_daily) == 0 ||
                copy_one_file(src_path, dst_daily) == 0) {
                have_daily = 1; break;
            }
        }
    }
    return (have_main && have_daily) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Unpacking                                                          */
/* ------------------------------------------------------------------ */

static int run_sigtool_unpack(const char *cvd_name) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
        }
        execlp("sigtool", "sigtool", "--unpack", cvd_name, (char *)NULL);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status)) return -1;
    return (WEXITSTATUS(status) == 0) ? 0 : -1;
}

static int run_tar_unpack(const char *cvd_name, const char *dest_dir) {
    const char *flags[] = { "-xzf", "-xf", "--zstd -xf", "-xJf", NULL };

    for (int i = 0; flags[i]; i++) {
        char cmd[2048];
        snprintf(cmd, sizeof(cmd),
                 "tail -c +%d '%s' | tar %s - -C '%s'",
                 CVD_HEADER_SIZE + 1, cvd_name, flags[i], dest_dir);

        int rc = system(cmd);
        if (rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0) return 0;
    }
    return -1;
}

static void debug_list_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "[~] Cannot list %s: %s\n", dir, strerror(errno));
        return;
    }
    fprintf(stderr, "[~] Contents of %s:\n", dir);
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char path[PATHBUF];
        snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        struct stat st;
        if (stat(path, &st) == 0) {
            fprintf(stderr, "[~]   %-32s size=%-10lld mode=%04o\n",
                    entry->d_name, (long long)st.st_size,
                    (unsigned)(st.st_mode & 07777));
        } else {
            fprintf(stderr, "[~]   %s (stat failed)\n", entry->d_name);
        }
    }
    closedir(d);
}

static int unpack_one(const char *cvd_name, const char *scratch_dir) {
    if (run_sigtool_unpack(cvd_name) == 0) return 0;

    char scratch_root[PATHBUF];
    snprintf(scratch_root, sizeof(scratch_root),
             "%s/.unpack_%s", scratch_dir, cvd_name);

    char cmd[PATHBUF * 2];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s' && mkdir -p '%s'",
             scratch_root, scratch_root);
    if (system(cmd) != 0) return -1;

    if (run_tar_unpack(cvd_name, scratch_root) != 0) {
        fprintf(stderr, "[~] tar fallback failed for %s\n", cvd_name);
        debug_list_dir(scratch_root);
        return -1;
    }

    /* Force sane permissions on every extracted file before we try to
     * read them. tar preserves the archive's mode bits, and those can
     * be 0000 when the caller's umask is unusually restrictive. */
    {
        DIR *fix = opendir(scratch_root);
        if (fix) {
            struct dirent *fe;
            while ((fe = readdir(fix)) != NULL) {
                if (fe->d_name[0] == '.') continue;
                char fp[PATHBUF];
                snprintf(fp, sizeof(fp), "%s/%s", scratch_root, fe->d_name);
                chmod(fp, 0644);
            }
            closedir(fix);
        }
    }

    const char *expected_main[]  = { "main.hdb",  "main.ndb",  "main.ldb",
                                     "main.mdb",  "main.fp",   NULL };
    const char *expected_daily[] = { "daily.hdb", "daily.ndb", "daily.ldb",
                                     "daily.mdb", "daily.fp",  NULL };
    const char **list = (strncmp(cvd_name, "daily", 5) == 0)
                      ? expected_daily : expected_main;

    int found_any = 0, all_readable = 1;
    for (int i = 0; list[i]; i++) {
        char p[PATHBUF];
        snprintf(p, sizeof(p), "%s/%s", scratch_root, list[i]);
        if (file_is_nonempty(p)) {
            found_any = 1;
            if (!file_is_readable(p)) all_readable = 0;
        }
    }
    if (!found_any || !all_readable) {
        fprintf(stderr, "[~] Extraction produced no usable files for %s\n",
                cvd_name);
        debug_list_dir(scratch_root);
        return -1;
    }

    DIR *d = opendir(scratch_root);
    if (!d) return -1;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char src[PATHBUF], dst[PATHBUF];
        snprintf(src, sizeof(src), "%s/%s", scratch_root, entry->d_name);
        snprintf(dst, sizeof(dst), "%s/%s", scratch_dir,  entry->d_name);
        chmod(src, 0644);
        if (rename(src, dst) != 0) {
            if (copy_one_file(src, dst) != 0) {
                fprintf(stderr, "[~] Could not move %s -> %s: %s\n",
                        src, dst, strerror(errno));
            }
        }
    }
    closedir(d);

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", scratch_root);
    system(cmd);
    return 0;
}

static void cleanup_extracted(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        if (name[0] == '.') continue;
        if (strncmp(name, "main.",  5) != 0 &&
            strncmp(name, "daily.", 6) != 0) continue;
        const char *ext = strrchr(name, '.');
        if (ext && (strcmp(ext, ".cvd") == 0 || strcmp(ext, ".cld") == 0 ||
                    strcmp(ext, ".cvd.tmp") == 0 ||
                    strcmp(ext, ".cld.tmp") == 0))
            continue;
        char path[PATHBUF];
        snprintf(path, sizeof(path), "%s/%s", dir, name);
        unlink(path);
    }
    closedir(d);
}

static int unpack_databases(void) {
    char cwd[PATHBUF];
    if (!getcwd(cwd, sizeof(cwd))) { perror("[!] getcwd failed"); return -1; }
    if (chdir(DATABASE_DIR) != 0) {
        perror("[!] chdir(database) failed");
        return -1;
    }

    const char *main_file  = NULL;
    const char *daily_file = NULL;
    struct stat st;
    if (stat("main.cvd", &st) == 0)       main_file  = "main.cvd";
    else if (stat("main.cld", &st) == 0)  main_file  = "main.cld";
    if (stat("daily.cvd", &st) == 0)      daily_file = "daily.cvd";
    else if (stat("daily.cld", &st) == 0) daily_file = "daily.cld";

    int ret1 = main_file  ? unpack_one(main_file,  ".") : -1;
    int ret2 = daily_file ? unpack_one(daily_file, ".") : -1;

    if (chdir(cwd) != 0) {
        perror("[!] Could not return to original directory");
        return -1;
    }
    return (ret1 == 0 && ret2 == 0) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Freshness                                                          */
/* ------------------------------------------------------------------ */

static int has_any_extracted_signature(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    int found = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        const char *ext = strrchr(entry->d_name, '.');
        if (!ext) continue;
        if (strcmp(ext, ".hdb") == 0 || strcmp(ext, ".ndb") == 0 ||
            strcmp(ext, ".ldb") == 0 || strcmp(ext, ".mdb") == 0 ||
            strcmp(ext, ".fp")  == 0) {
            char path[PATHBUF];
            snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
            if (file_is_readable(path)) { found = 1; break; }
        }
    }
    closedir(d);
    return found;
}

static int database_is_fresh(void) {
    struct stat st;
    const char *paths[] = {
        DATABASE_DIR "/main.cvd",  DATABASE_DIR "/main.cld",
        DATABASE_DIR "/daily.cvd", DATABASE_DIR "/daily.cld",
    };
    int have_main = 0, have_daily = 0;
    size_t n = sizeof(paths) / sizeof(paths[0]);
    for (size_t i = 0; i < n; i++) {
        if (stat(paths[i], &st) != 0) continue;
        if (difftime(time(NULL), st.st_mtime) > SIX_WEEKS_SECONDS) continue;
        if (strstr(paths[i], "main"))  have_main  = 1;
        if (strstr(paths[i], "daily")) have_daily = 1;
    }
    if (!have_main || !have_daily) return 0;
    return has_any_extracted_signature(DATABASE_DIR);
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                 */
/* ------------------------------------------------------------------ */

int update_if_needed(int force_update) {
    if (ensure_directory_exists(DATABASE_DIR) != 0) return -1;

    const char *MAIN_FINAL = DATABASE_DIR "/main.cvd";
    const char *DAILY_FINAL = DATABASE_DIR "/daily.cvd";
    const char *MAIN_TMP   = DATABASE_DIR "/main.cvd.tmp";
    const char *DAILY_TMP  = DATABASE_DIR "/daily.cvd.tmp";

    /* Decide what we actually need to (re)fetch. If a CVD is present,
     * non-empty and recent, and force_update is off, keep it. This
     * avoids hammering the CDN for the file we already have. */
    int need_main  = force_update
                  || !file_is_nonempty(MAIN_FINAL)
                  || file_is_stale(MAIN_FINAL, SIX_WEEKS_SECONDS);
    int need_daily = force_update
                  || !file_is_nonempty(DAILY_FINAL)
                  || file_is_stale(DAILY_FINAL, SIX_WEEKS_SECONDS);

    if (!need_main && !need_daily && database_is_fresh()) {
        printf("[+] Signature database is up-to-date.\n");
        return 0;
    }

    printf("[*] Updating ClamAV signature databases...\n");
    if (need_main)  printf("[~] main.cvd needs refresh\n");
    if (need_daily) printf("[~] daily.cvd needs refresh\n");

    unlink(MAIN_TMP);
    unlink(DAILY_TMP);

    /* ---- Strategy 1: direct download (only what we need) ---- */
    if (need_main) {
        if (download_file(MAIN_URL, MAIN_TMP) == 0 &&
            rename(MAIN_TMP, MAIN_FINAL) == 0) {
            need_main = 0;
        } else {
            unlink(MAIN_TMP);
            if (file_is_nonempty(MAIN_FINAL)) {
                fprintf(stderr, "[~] Keeping existing main.cvd\n");
                need_main = 0;
            }
        }
    }
    if (need_daily) {
        if (download_file(DAILY_URL, DAILY_TMP) == 0 &&
            rename(DAILY_TMP, DAILY_FINAL) == 0) {
            need_daily = 0;
        } else {
            unlink(DAILY_TMP);
            if (file_is_nonempty(DAILY_FINAL)) {
                fprintf(stderr, "[~] Keeping existing daily.cvd\n");
                need_daily = 0;
            }
        }
    }

    /* ---- Strategy 2: freshclam fills in whatever is still missing ---- */
    if (need_main || need_daily) {
        printf("[~] Trying 'freshclam' for missing files...\n");
        if (run_freshclam(DATABASE_DIR) == 0) {
            if (need_main  && file_is_nonempty(MAIN_FINAL))  need_main  = 0;
            if (need_daily && file_is_nonempty(DAILY_FINAL)) need_daily = 0;
            if (need_main || need_daily) {
                copy_from_dir(DATABASE_DIR, MAIN_FINAL, DAILY_FINAL);
                if (file_is_nonempty(MAIN_FINAL))  need_main  = 0;
                if (file_is_nonempty(DAILY_FINAL)) need_daily = 0;
            }
        }
    }

    /* ---- Strategy 3: system ClamAV install ---- */
    if (need_main && file_is_nonempty(SYSTEM_MAIN_CVD)) {
        printf("[~] Copying system main.cvd from %s\n", SYSTEM_CLAMAV_DIR);
        if (copy_one_file(SYSTEM_MAIN_CVD, MAIN_FINAL) == 0) need_main = 0;
    }
    if (need_daily && file_is_nonempty(SYSTEM_DAILY_CVD)) {
        printf("[~] Copying system daily.cvd from %s\n", SYSTEM_CLAMAV_DIR);
        if (copy_one_file(SYSTEM_DAILY_CVD, DAILY_FINAL) == 0) need_daily = 0;
    }

    if (need_main || need_daily) {
        fprintf(stderr,
            "[!] Could not obtain all signature databases.\n"
            "    Still missing: %s%s%s\n"
            "    Install ClamAV for a guaranteed fallback:\n"
            "      sudo apt install -y clamav clamav-freshclam\n",
            need_main ? "main.cvd " : "",
            need_daily ? "daily.cvd" : "",
            "");
        return -1;
    }

    /* ---- Unpack whatever is currently on disk ---- */
    cleanup_extracted(DATABASE_DIR);

    if (unpack_databases() != 0) {
        fprintf(stderr, "[!] Failed to unpack .cvd files.\n");
        fprintf(stderr, "    Install ClamAV for its 'sigtool' utility:\n");
        fprintf(stderr, "      sudo apt install -y clamav\n");
        debug_list_dir(DATABASE_DIR);
        return -1;
    }

    if (!has_any_extracted_signature(DATABASE_DIR)) {
        fprintf(stderr, "[!] Unpacking completed but no readable "
                        "signature file was found.\n");
        debug_list_dir(DATABASE_DIR);
        return -1;
    }

    printf("[+] Database update completed.\n");
    return 0;
}
