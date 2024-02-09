#include "device.h"
#include <erl_nif.h>

int add(int a, int b) { return a + b; }

ERL_NIF_TERM add_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  int a = 0;
  int b = 0;

  if (!enif_get_int(env, argv[0], &a)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_int(env, argv[1], &b)) {
    return enif_make_badarg(env);
  }

  int result = add(a, b);
  return enif_make_int(env, result);
}

ERL_NIF_TERM device_list_all_nif(ErlNifEnv *env, int argc,
                                 const ERL_NIF_TERM argv[]) {
  std::vector<std::string> result;
  result = Device::list_all();

  ERL_NIF_TERM list = enif_make_list(env, 0);
  for (auto i = result.begin(); i != result.end(); ++i) {
    ERL_NIF_TERM item = enif_make_string(env, i->c_str(), ERL_NIF_LATIN1);
    list = enif_make_list_cell(env, item, list);
  }

  return list;
}

ErlNifFunc nif_funcs[] = {{"list_all", 0, device_list_all_nif}};

ERL_NIF_INIT(Elixir.ExWire.Device, nif_funcs, nullptr, nullptr, nullptr,
             nullptr);
