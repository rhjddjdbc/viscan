#ifndef UPDATE_DATABASE_H
#define UPDATE_DATABASE_H

// Call this in main()
// force_update = 1 => always update
// force_update = 0 => only update if older than 6 weeks
int update_if_needed(int force_update);

#endif
