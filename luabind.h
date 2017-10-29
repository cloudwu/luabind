#ifndef LUA_BIND_H
#define LUA_BIND_H

#include <lua.h>

#define LF_NOTFOUND 1
#define LF_ERRPARSE 2
#define LF_ERRRUN 3

#define LT_NIL 0
#define LT_INTEGER 1
#define LT_REAL 2
#define LT_STRING 3
#define LT_LSTRING 4
#define LT_BOOLEAN 5
#define LT_POINTER 6
#define LT_NONE -1

// not implement now
#define LT_ARRAY 7
#define LT_MAP 8

struct vars;

struct vars * lbind_new();
void lbind_delete(struct vars *v);
void lbind_clear(struct vars *v);

int lbind_type(struct vars *v, int index);
int lbind_tointeger(struct vars *v, int index);
double lbind_toreal(struct vars *v, int index);
const char * lbind_tostring(struct vars *v, int index);
int lbind_toboolean(struct vars *v, int index);
void * lbind_topointer(struct vars *v, int index);

//int lbind_openarray(struct vars *v);
//int lbind_openmap(struct vars *v);
//int lbind_close(struct vars *v);
int lbind_pushinteger(struct vars *v, int i);
int lbind_pushreal(struct vars *v, double f);
int lbind_pushstring(struct vars *v, const char *s);
int lbind_pushlstring(struct vars *v, const char *s, size_t len);
int lbind_pushboolean(struct vars *v, int b);
int lbind_pushnil(struct vars *v);
int lbind_pushpointer(struct vars *v, void *p);

typedef void (*lbind_function)(struct vars *input , struct vars *output);

struct vars * lbind_args(lua_State *L);
struct vars * lbind_call(lua_State *L, const char * funcname, struct vars *args);
void lbind_register(lua_State *L, const char * funcname, lbind_function f);
int lbind_dofile(lua_State *L, const char * filename);

#endif
