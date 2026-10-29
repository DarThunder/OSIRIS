{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  packages = [
    (pkgs.python3.withPackages (ps: with ps; [
      fastapi
      uvicorn
      sqlalchemy
      pydantic
      pyjwt
      cryptography
      argon2-cffi
      httpx
      python-dotenv
    ]))
    pkgs.sqlite
  ];

  shellHook = ''
    export PYTHONPYCACHEPREFIX="''$PWD/.cache/osiris"
    echo "Hola Charlie."
  '';
}