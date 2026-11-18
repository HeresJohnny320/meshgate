// C API of libmeshcore for the iOS/macOS apps (implemented in
// rust/meshcore/src/capi.rs). Swift wrappers: go/mobile/ios/Shared/Meshcore.swift.
//
// Returned strings are owned by the caller: free them with mc_string_free.
// `err` out parameters are set to NULL on success or to an error message.
#ifndef MESHCORE_H
#define MESHCORE_H

#include <stdbool.h>
#include <stdint.h>

typedef struct mc_engine mc_engine;

typedef struct {
    void *ctx;
    bool (*protect)(void *ctx, int32_t fd);
    int32_t (*configure_tunnel)(void *ctx, const char *settings_json);
    // Returns a malloc'd string the library frees, or NULL.
    char *(*local_addresses)(void *ctx);
    void (*log)(void *ctx, const char *msg);
    // Called once when the engine no longer needs ctx.
    void (*release)(void *ctx);
} mc_platform;

void mc_string_free(char *s);

mc_engine *mc_engine_new(const char *dir, mc_platform plat, char **err);
void mc_engine_free(mc_engine *h);

bool mc_engine_is_joined(const mc_engine *h);
bool mc_engine_join(const mc_engine *h, const char *token, const char *name, char **err);
bool mc_engine_leave(const mc_engine *h, char **err);
bool mc_engine_start(const mc_engine *h, char **err);
void mc_engine_stop(const mc_engine *h);
void mc_engine_network_changed(const mc_engine *h);
char *mc_engine_status_json(const mc_engine *h);
char *mc_engine_diag(const mc_engine *h, const char *kind, const char *target, int64_t port);
bool mc_engine_set_exit_choice(const mc_engine *h, const char *id, char **err);
bool mc_engine_kill_switch(const mc_engine *h);
bool mc_engine_set_kill_switch(const mc_engine *h, bool on, char **err);
char *mc_engine_admin(const mc_engine *h, const char *method, const char *path, const char *body);
char *mc_engine_update_available(const mc_engine *h, const char *app_version);
char *mc_engine_changelog(const mc_engine *h);

#endif
