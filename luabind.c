#include "luabind.h"

#include <lua.h>
#include <lauxlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

struct lstr
{
	const char *s;
	size_t sz;
};

struct lvar {
	int type;
	union {
		lua_Integer i;
		lua_Number f;
		const char * s;
		struct lstr *ls;
		int b;
		void *p;
//		struct larray *a;
//		struct lmap *m;
	} v;
};

struct vars {
	int n;
	int cap;
	struct lvar *v;
};

struct vars *
lbind_new() {
	struct vars *v = malloc(sizeof(*v));
	if (v == NULL)
		return NULL;
	v->n = 0;
	v->cap = 0;
	v->v = NULL;
	return v;
}

void
lbind_delete(struct vars *v) {
	if (v == NULL)
		return;
	if (v->v) {
		free(v->v);
	}
	free(v);
}

void
lbind_clear(struct vars *v) {
	v->n = 0;
}

int
lbind_type(struct vars *v, int index) {
	if (index < 0 || index >=v->n) {
		return LT_NONE;
	}
	return v->v[index].type;
}

int
lbind_tointeger(struct vars *v, int index) {
	if (index < 0 || index >=v->n) {
		return 0;
	}
	return v->v[index].v.i;
}


double
lbind_toreal(struct vars *v, int index) {
	if (index < 0 || index >=v->n) {
		return 0;
	}
	return v->v[index].v.f;
}

const char *
lbind_tostring(struct vars *v, int index) {
	if (index < 0 || index >=v->n) {
		return 0;
	}
	return v->v[index].v.s;
}

int
lbind_toboolean(struct vars *v, int index) {
	if (index < 0 || index >=v->n) {
		return 0;
	}
	return v->v[index].v.b;
}

void *
lbind_topointer(struct vars *v, int index) {
	if (index < 0 || index >=v->n) {
		return 0;
	}
	return v->v[index].v.p;
}

static struct lvar *
newvalue(struct vars *v) {
	if (v->n >= v->cap) {
		int cap = v->cap * 2;
		if (cap == 0) {
			cap = 16;
		}
		struct lvar * nv = malloc(cap * sizeof(*nv));
		if (nv == NULL)
			return NULL;
		memcpy(nv, v->v, v->n * sizeof(*nv));
		free(v->v);
		v->v = nv;
		v->cap = cap;
	}
	struct lvar * ret = &v->v[v->n];
	++v->n;
	return ret;
}

int
lbind_pushinteger(struct vars *v, int i) {
	struct lvar * s = newvalue(v);
	if (s == NULL)
		return -1;
	s->type = LT_INTEGER;
	s->v.i = i;
	return 0;
}

int
lbind_pushreal(struct vars *v, double f) {
	struct lvar * s = newvalue(v);
	if (s == NULL)
		return -1;
	s->type = LT_REAL;
	s->v.f = f;
	return 0;
}

int
lbind_pushstring(struct vars *v, const char *str) {
	struct lvar * s = newvalue(v);
	if (s == NULL)
		return -1;
	s->type = LT_STRING;
	s->v.s = str;
	return 0;
}

int 
lbind_pushlstring(struct vars *v, const char *s, size_t sz)
{
	struct lvar * ls = newvalue(v);
	if (ls == NULL)
		return -1;
	ls->type = LT_LSTRING;
	ls->v.ls = malloc(sizeof(*(ls->v.ls)));
	assert(ls->v.ls);
	ls->v.ls->s = s;
	ls->v.ls->sz = sz;
	return 0;
}

int
lbind_pushboolean(struct vars *v, int b) {
	struct lvar * s = newvalue(v);
	if (s == NULL)
		return -1;
	s->type = LT_BOOLEAN;
	s->v.b = b;
	return 0;
}

int
lbind_pushnil(struct vars *v) {
	struct lvar * s = newvalue(v);
	if (s == NULL)
		return -1;
	s->type = LT_NIL;
	return 0;
}

int
lbind_pushpointer(struct vars *v, void *p) {
	struct lvar * s = newvalue(v);
	if (s == NULL)
		return -1;
	s->type = LT_POINTER;
	s->v.p = p;
	return 0;
}

static int
ldelvars(lua_State *L) {
	struct vars ** box = (struct vars **)lua_touserdata(L,1);
	if (*box) {
		lbind_delete(*box);
		*box = NULL;
	}
	return 0;
}

static struct vars *
newvarsobject(lua_State *L) {
	struct vars ** box = (struct vars **)lua_newuserdata(L, sizeof(*box));
	*box = NULL;
	struct vars * v = lbind_new();
	if (v == NULL) {
		return NULL;
	}
	*box = NULL;
	if (luaL_newmetatable(L, "luabindvars")) {
		lua_pushcfunction(L, ldelvars);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);

	*box = v;
	return v;
}

// v -> lua stack
static int
pushargs(lua_State *L, struct vars *vars) {
	if (vars == NULL)
		return 0;
	int n = vars->n;
	luaL_checkstack(L, n, NULL);
	int i;
	for (i=0;i<n;i++) {
		struct lvar *v = &vars->v[i];
		switch(v->type) {
		case LT_NIL:
			lua_pushnil(L);
			break;
		case LT_INTEGER:
			lua_pushinteger(L, v->v.i);
			break;
		case LT_REAL:
			lua_pushnumber(L, v->v.f);
			break;
		case LT_STRING:
			lua_pushstring(L, v->v.s);
			break;
		case LT_LSTRING:
			lua_pushlstring(L, v->v.ls->s, v->v.ls->sz);
			free(v->v.ls);
			break;
		case LT_BOOLEAN:
			lua_pushboolean(L, v->v.b);
			break;
		case LT_POINTER:
			lua_pushlightuserdata(L, v->v.p);
			break;
		case LT_ARRAY : //todo
		case LT_MAP : //todo
		default :
			luaL_error(L, "unsupport type %d", v->type);
		}
	}
	return n;
}

// lua stack -> v
static void
genargs(lua_State *L, struct vars *v) {
	int n = lua_gettop(L);
	int i;
	for (i=1;i<=n;i++) {
		int err = 0;
		int t = lua_type(L, i);
		switch(t) {
		case LUA_TNIL:
			err = lbind_pushnil(v);
			break;
		case LUA_TBOOLEAN:
			err = lbind_pushboolean(v, lua_toboolean(L, i));
			break;
		case LUA_TNUMBER:
			if (lua_isinteger(L, i)) {
				err = lbind_pushinteger(v, lua_tointeger(L, i));
			} else {
				err = lbind_pushreal(v, lua_tonumber(L, i));
			}
			break;
		case LUA_TSTRING:
			err = lbind_pushstring(v, lua_tostring(L, i));
			break;
		case LUA_TLIGHTUSERDATA:
			err = lbind_pushpointer(v, lua_touserdata(L, i));
			break;
		case LUA_TTABLE:	// todo
		default:
			luaL_error(L, "unsupport type %s", lua_typename(L, t));
		}
		if (err) {
			luaL_error(L, "push arg %d error", i);
		}
	}
}

static struct vars *
getvars(lua_State *L, void *p) {
	struct vars *args = NULL;
	lua_rawgetp(L, LUA_REGISTRYINDEX, p);
	if (lua_isuserdata(L, -1)) {
		struct vars ** box = (struct vars **)lua_touserdata(L, -1);
		args = *box;
		lua_pop(L,1);
	} else {
		lua_pop(L,1);
		args = newvarsobject(L);
		if (args == NULL)
			luaL_error(L, "new result object failed");
		lua_rawsetp(L, LUA_REGISTRYINDEX, p);
	}
	lbind_clear(args);
	return args;
}

static struct vars *
resultvars(lua_State *L) {
	static int result = 0;
	return getvars(L, &result);
}

static struct vars *
argvars(lua_State *L, int onlyfetch) {
	static int args = 0;
	if (onlyfetch) {
		lua_rawgetp(L, LUA_REGISTRYINDEX, &args);
		if (lua_isuserdata(L, -1)) {
			struct vars ** box = (struct vars **)lua_touserdata(L, -1);
			lua_pop(L,1);
			return *box;
		} else {
			lua_pop(L,1);
			return NULL;
		}
	} else {
		return getvars(L, &args);
	}
}

static int
lnewargs(lua_State *L) {
	struct vars * args = argvars(L, 0);
	lua_pushlightuserdata(L, args);
	return 1;
}

static void
errorlog(lua_State *L) {
	fprintf(stderr, "Error: %s\n", lua_tostring(L, -1));
	lua_pop(L, 1);
}

struct vars *
lbind_args(lua_State *L) {
	struct vars * args = argvars(L,1);	// try fetch args, never raise error
	if (args)
		return args;
	lua_pushcfunction(L, lnewargs);
	if (lua_pcall(L,0,1,0) != LUA_OK) {
		errorlog(L);
		return NULL;
	}
	args = lua_touserdata(L, -1);
	lua_pop(L, 1);
	return args;
}

static int
lcall(lua_State *L) {
	const char * funcname = lua_touserdata(L, 1);
	struct vars *args = lua_touserdata(L,2);
	lua_settop(L, 0);
	if (lua_getglobal(L, funcname) != LUA_TFUNCTION) {
		return luaL_error(L, "%s is not a function", funcname);
	}
	lua_call(L, pushargs(L, args), LUA_MULTRET);
	luaL_checkstack(L, LUA_MINSTACK, NULL);
	args = resultvars(L);
	genargs(L, args);
	lua_pushlightuserdata(L, args);
	return 1;
}

struct vars *
lbind_call(lua_State *L, const char * funcname, struct vars *args) {
	lua_pushcfunction(L, lcall);
	lua_pushlightuserdata(L, (void *)funcname);
	lua_pushlightuserdata(L, args);
	int ret = lua_pcall(L, 2, 1, 0);
	if (ret == LUA_OK) {
		struct vars * result = lua_touserdata(L,-1);
		lua_pop(L, 1);
		return result;
	} else {
		// ignore the error message, If you  need log error message, use lua_tostring(L, -1)
		errorlog(L);
		return NULL;
	}
}

static int
lfunc(lua_State *L) {
	lbind_function f = (lbind_function)lua_touserdata(L, lua_upvalueindex(1));
	struct vars * args = argvars(L,0);
	struct vars * result = resultvars(L);
	genargs(L, args);
	f(args, result);
	lbind_clear(args);
	lua_settop(L, 0);
	int n = pushargs(L, result);
	lbind_clear(result);

	return n;
}

static int
lregister(lua_State *L) {
	const char * funcname = lua_touserdata(L, 1);
	luaL_checktype(L, 2, LUA_TLIGHTUSERDATA);
	if (lua_getglobal(L, "C") != LUA_TTABLE) {
		lua_newtable(L);
		lua_pushvalue(L, -1);
		lua_setglobal(L, "C");
	}
	lua_pushvalue(L, 2);
	lua_pushcclosure(L, lfunc, 1);
	lua_setfield(L, -2, funcname);

	return 0;
}

void
lbind_register(lua_State *L, const char * funcname, lbind_function f) {
	lua_pushcfunction(L, lregister);
	lua_pushlightuserdata(L, (void *)funcname);
	lua_pushlightuserdata(L, f);
	int ret = lua_pcall(L, 2, 0, 0);
	if (ret != LUA_OK) {
		// ignore the error message, If you  need log error message, use lua_tostring(L, -1)
		errorlog(L);
	}
}

static int
ldofile(lua_State *L) {
	const char * filename = (const char *)lua_touserdata(L, 1);
	int ret = luaL_loadfile(L, filename);
	if (ret != LUA_OK) {
		// ignore the error message
		errorlog(L);
		if (ret == LUA_ERRFILE) {
			lua_pushinteger(L, LF_NOTFOUND);
		} else {
			lua_pushinteger(L, LF_ERRPARSE);
		}
		return 1;
	}
	ret = lua_pcall(L, 0, 0, 0);
	if (ret != LUA_OK) {
		// ignore the error message
		errorlog(L);
		lua_pushinteger(L, LF_ERRRUN);
		return 1;
	}
	lua_pushinteger(L, 0);
	return 1;
}

int
lbind_dofile(lua_State *L, const char * filename) {
	lua_pushcfunction(L, ldofile);
	lua_pushlightuserdata(L, (void *)filename);
	int ret = lua_pcall(L, 1, 1, 0);
	if (ret != LUA_OK) {
		// ignore the error message, If you need log error message, use lua_tostring(L, -1)
		errorlog(L);
		return -1;
	} else {
		int ret = lua_tointeger(L, -1);
		lua_pop(L, 1);
		return ret;
	}
}
