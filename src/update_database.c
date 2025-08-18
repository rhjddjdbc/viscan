#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <curl/curl.h>
#include <unistd.h>

#include "update_database.h"

#define DATABASE_DIR "database"
#define MAIN_URL "https://database.clamav.net/main.cvd"
#define DAILY_URL "https://database.clamav.net/daily.cvd"
#define SIX_WEEKS_SECONDS (6 * 7 * 24 * 60 * 60)

int file_is_older_than(const char *path, time_t seconds) {
    struct stat st;
    if (stat(path, &st) != 0) return 1; // Not found
    time_t now = time(NULL);
    return difftime(now, st.st_mtime) > seconds;
}

int download_file(const char *url, const char *out_path) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    FILE *fp = fopen(out_path, "wb");
    if (!fp) {
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

    CURLcode res = curl_easy_perform(curl);
    fclose(fp);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}

int ensure_directory_exists(const char *path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        return mkdir(path, 0755);
    }
    return 0;
}

int unpack_databases() {
    char cwd[1024];
    if (!getcwd(cwd, sizeof(cwd))) {
        perror("[!] Failed to get current directory");
        return -1;
    }

    // Change to database/ directory
    if (chdir("database") != 0) {
        perror("[!] Failed to change to database/ directory");
        return -1;
    }

    // Unpack both .cvd files inside database/
    int ret1 = system("sigtool --unpack main.cvd");
    int ret2 = system("sigtool --unpack daily.cvd");

    // Return to original directory
    if (chdir(cwd) != 0) {
        perror("[!] Failed to return to original directory");
        return -1;
    }

    return (ret1 == 0 && ret2 == 0) ? 0 : -1;
}

int update_if_needed(int force_update) {
    ensure_directory_exists(DATABASE_DIR);

    char main_path[256];
    char daily_path[256];
    snprintf(main_path, sizeof(main_path), "%s/main.cvd", DATABASE_DIR);
    snprintf(daily_path, sizeof(daily_path), "%s/daily.cvd", DATABASE_DIR);

    int update_main = file_is_older_than(main_path, SIX_WEEKS_SECONDS);
    int update_daily = file_is_older_than(daily_path, SIX_WEEKS_SECONDS);

    if (!force_update && !update_main && !update_daily) {
        printf("[+] Signature database is up-to-date.\n");
        return 0;
    }

    printf("[*] Updating ClamAV signature databases...\n");

    if (download_file(MAIN_URL, main_path) != 0) {
        fprintf(stderr, "[!] Failed to download main.cvd\n");
        return -1;
    }

    if (download_file(DAILY_URL, daily_path) != 0) {
        fprintf(stderr, "[!] Failed to download daily.cvd\n");
        return -1;
    }

    if (unpack_databases() != 0) {
        fprintf(stderr, "[!] Failed to unpack .cvd files\n");
        return -1;
    }

    printf("[+] Database update completed.\n");
    return 0;
}
