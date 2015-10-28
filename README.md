esel
=====

An OTP application

Build
-----

    $ rebar3 compile

```erlang
{ok, Key} = esel:genrsa(2048).
{ok, Req} = esel:req("this-is-the-subject", Key).
{ok, Cert} = esel:sign_csr(365, Req).
esel_cert:fingerprint(Cert).
esel_cert:cn(Cert).
```