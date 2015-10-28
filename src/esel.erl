%%%-------------------------------------------------------------------
%%% @author Heinz Nikolaus Gies <heinz@licenser.net>
%%% @copyright (C) 2015, Heinz Nikolaus Gies
%%% @doc
%%%
%%% @end
%%% Created : 28 Oct 2015 by Heinz Nikolaus Gies <heinz@licenser.net>
%%%-------------------------------------------------------------------
-module(esel).

-behaviour(gen_server).

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, genrsa/1, req/2, sign_csr/2]).

-define(SERVER, ?MODULE).

-record(state, {
          ca_cert :: string(),
          ca_key :: string(),
          openssl :: string(),
          pass :: string()
         }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%--------------------------------------------------------------------
%% @doc
%% Generates a RSA private key.
%%
%% @end
%%--------------------------------------------------------------------
-spec genrsa(binary()) -> {ok, Binary} | {error, term()}.
genrsa(Bytes) when is_integer(Bytes) ->
    gen_server:call(?SERVER, {genrsa, Bytes}, 60000).

%%--------------------------------------------------------------------
%% @doc
%% Generates a CSR for a private key.
%%
%% @end
%%--------------------------------------------------------------------
-spec req(string(), binary()) -> {ok, Binary} | {error, term()}.
req(Subject, Key) when is_binary(Key) ->
    gen_server:call(?SERVER, {req, Subject, Key}).

%%--------------------------------------------------------------------
%% @doc
%% Generates a signed certificate for a CSR
%%
%% @end
%%--------------------------------------------------------------------
-spec req(pos_integer(), binary()) -> {ok, Binary} | {error, term()}.
sign_csr(Days, CSR) when is_binary(CSR), is_integer(Days), Days > 0 ->
    gen_server:call(?SERVER, {sign_csr, Days, CSR}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    {ok, CACert} = application:get_env(esel, ca_cert),
    {ok, CAKey} = application:get_env(esel, ca_key),
    {ok, CAPass} = application:get_env(esel, ca_pass),
    OpenSSL = application:get_env(esel, ca_dir, os:find_executable("openssl")),
    {ok, #state{
            ca_cert = CACert,
            ca_key = CAKey,
            openssl = OpenSSL,
            pass = CAPass
           }}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({genrsa, Bytes}, _From, State) ->
    KeyFile = mktemp(),
    case openssl(genrsa, [{out, KeyFile}, Bytes], State) of
        {ok, _} ->
            Reply = file:read_file(KeyFile),
            ok = file:delete(KeyFile),
            {reply, Reply, State};
        E ->
            file:delete(KeyFile),
            {reply, E, State}
    end;

handle_call({req, Subject, Key}, _From, State) ->
    KeyFile = mktemp(),
    CsrFile = mktemp(),
    file:write_file(KeyFile, Key),
    case openssl(req, [{subj, "/CN=" ++ Subject}, new,
                       {key, KeyFile}, {out, CsrFile}], State) of
        {ok, _} ->
            ok = file:delete(KeyFile),
            Reply = file:read_file(CsrFile),
            ok = file:delete(CsrFile),
            {reply, Reply, State};
        E ->
            ok = file:delete(KeyFile),
            file:delete(CsrFile),
            {reply, E, State}
    end;

handle_call({sign_csr, Days, CSR}, _From,
            State = #state{pass = Pass, ca_cert = CACert, ca_key = CAKey}) ->
    CsrFile = mktemp(),
    ExtFile = mktemp(),
    CertFile = mktemp(),
    file:write_file(ExtFile, "extendedKeyUsage = clientAuth\n"),

    file:write_file(CsrFile, CSR),

    case openssl(x509,
                 [req, {days, Days}, sha256, {in, CsrFile}, {'CA', CACert},
                  {passin, "pass:" ++ Pass}, {set_serial, mk_serial()},
                  {'CAkey', CAKey}, 'CAcreateserial', {out, CertFile},
                  {extfile, ExtFile}], State) of
        {ok, _} ->
            ok = file:delete(ExtFile),
            ok = file:delete(CsrFile),
            Reply = file:read_file(CertFile),
            ok = file:delete(CertFile),
            {reply, Reply, State};
        E ->
            ok = file:delete(ExtFile),
            ok = file:delete(CsrFile),
            file:delete(CertFile),
            {reply, E, State}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%openssl genrsa -out key.pem 4096
openssl(Command, ArgsIn, #state{openssl = OpenSSL}) ->
    Args = [atom_to_list(Command) | mk_args(ArgsIn)],
    Port = open_port({spawn_executable, OpenSSL},
                     [use_stdio, binary, {line, 1000}, {args, Args}, stderr_to_stdout,
                      exit_status]),
    wait_for_port(Port).

mk_args([]) ->
    [];
mk_args([{K, V} | R]) ->
    [ mk_val(K), mk_val(V) | mk_args(R)];
mk_args([K | R]) ->
    [ mk_val(K) | mk_args(R)].

mk_val(I) when is_integer(I) ->
    integer_to_list(I);
mk_val(A) when is_atom(A) ->
    [$- | atom_to_list(A)];
mk_val(L) when is_list(L)->
    L;
mk_val(B) when is_binary(B) ->
    binary_to_list(B).

wait_for_port(Port) ->
    wait_for_port(Port, <<>>).
wait_for_port(Port, Reply) ->
    receive
        {Port, {data, {eol, Data}}} ->
            wait_for_port(Port, <<Reply/binary, Data/binary>>);
        {Port, {data, Data}} ->
            wait_for_port(Port, <<Reply/binary, Data/binary>>);
        {Port,{exit_status, 0}} ->
            {ok, Reply};
        {Port,{exit_status, S}} ->
            {error, S, Reply}
    end.

mktemp() ->
    lib:nonl(os:cmd("mktemp")).

mk_serial() ->
    H = erlang:phash2(node()),
    T = erlang:monotonic_time(milli_seconds),
    U = erlang:unique_integer([positive]),
    <<I:128/unsigned-integer>> = <<H:32, T:64, U:32>>,
    I.
