#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <assert.h>
#include <stdbool.h>

#include "luabind.h"

static void
foobar(struct vars *input, struct vars *output) {
	assert(lbind_type(input, 0) == LT_INTEGER);
	int a = lbind_tointeger(input, 0);
	lbind_pushinteger(output, a*2);
}

int
main() {
	lua_State *L = luaL_newstate();
    assert(L);

	luaL_openlibs(L);

	lbind_register(L, "double", foobar);

	lbind_dofile(L, "test.lua");

    struct vars * args = lbind_args(L);
    lbind_pushstring(args, "foobar");

    struct vars * result = lbind_call(L, "hello", args);
    lbind_clear(args);

    assert(lbind_type(result, 0) == LT_INTEGER);
    printf("sizeof 'foobar' = %d\n", lbind_tointeger(result, 0));

    lbind_pushnil(args);
    lbind_pushpointer(args, L);
    lbind_pushboolean(args, true);
    lbind_pushreal(args, 3.1415);
    lbind_pushinteger(args, 3);
    lbind_pushstring(args, "testing");

    result = lbind_call(L, "trans", args);
    lbind_clear(args);

    assert(lbind_type(result, 0) == LT_NIL);
    assert(lbind_type(result, 1) == LT_POINTER);
    assert(lbind_type(result, 2) == LT_BOOLEAN);
    assert(lbind_type(result, 3) == LT_REAL);
    assert(lbind_type(result, 4) == LT_INTEGER);
    assert(lbind_type(result, 5) == LT_STRING);

	lua_close(L);
	return 0;
}

