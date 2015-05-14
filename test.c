#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <assert.h>

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
	luaL_openlibs(L);

	lbind_register(L, "double", foobar);

	lbind_dofile(L, "test.lua");

	struct vars * args = lbind_args(L);
	lbind_pushstring(args, "foobar");
	struct vars * result = lbind_call(L, "hello", args);
	assert(lbind_type(result, 0) == LT_INTEGER);
	printf("sizeof 'foobar' = %d\n", lbind_tointeger(result, 0));

	lua_close(L);
	return 0;
}


