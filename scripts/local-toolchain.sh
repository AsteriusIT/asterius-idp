#!/usr/bin/env bash
# Reports which build accelerators this machine has, and prints the
# `~/.cargo/config.toml` snippet that turns them on.
#
#   scripts/local-toolchain.sh            # what is installed, what is active
#   scripts/local-toolchain.sh --print    # just the snippet, for copy-paste
#
# Why it prints instead of writing, and why the snippet goes in your home
# directory rather than in `.cargo/config.toml` of the repository: a config
# that names `mold` or `sccache` is a hard requirement for every reader of that
# file. On a machine -- or a CI runner -- without them, every single build dies
# with "linker `mold` not found" or "no such file or directory: sccache". Cargo
# has no "use it if present" syntax, so the choice is per machine, and per
# machine means `~/.cargo/config.toml`. Both settings are absent from the
# repository config, so the home one is what applies (of two config files that
# define the same key, the one closest to the working directory wins).
#
#   mold     links the ~30 statically linked test binaries of this workspace in
#            a fraction of the time GNU ld takes. Saves no disk.
#   sccache  a content-addressed compilation cache shared by every worktree, so
#            a fresh agent worktree does not rebuild the dependency tree from
#            cold. Needs `build.incremental = false`, which the repository
#            config already sets: sccache declines to cache incremental
#            compilation. The `target/` directories stay separate on purpose --
#            see CONTRIBUTING.md, "Disk space", on the shared-CARGO_TARGET_DIR
#            trap.
set -uo pipefail

PRINT_ONLY=0
case "${1:-}" in
  --print) PRINT_ONLY=1 ;;
  '') ;;
  -h | --help)
    sed -n '2,7p' "$0"
    exit 0
    ;;
  *)
    echo "option inconnue : $1" >&2
    exit 2
    ;;
esac

USER_CONFIG="${CARGO_HOME:-$HOME/.cargo}/config.toml"

mold_bin="$(command -v mold || true)"
sccache_bin="$(command -v sccache || true)"
# The owner's mold is installed outside the default PATH of a non-login shell.
[ -z "$mold_bin" ] && [ -x "$HOME/.local/bin/mold" ] && mold_bin="$HOME/.local/bin/mold"

# Two flags, both needed, verified on rustc 1.98 + gcc 13:
#
#   -C linker-features=-lld   rustc now passes `-fuse-ld=lld` by default on
#                             x86_64-linux and points `cc` at its bundled
#                             `rust-lld`. Without this, mold is simply ignored.
#   -C link-arg=-B<dir>       mold ships a directory containing an `ld` symlink
#                             to itself; `-B` makes `cc` find it. Not
#                             `-fuse-ld=<path>`: gcc rejects a path there, that
#                             spelling is clang-only.
#
# Because the default is already LLD and no longer GNU ld, mold buys less than
# the folklore says. It still links this workspace's ~30 statically linked test
# binaries faster, and it is free to try.
mold_flag=""
mold_note=""
if [ -n "$mold_bin" ]; then
  mold_dir="$(dirname "$(dirname "$mold_bin")")/libexec/mold"
  if [ -e "$mold_dir/ld" ]; then
    mold_flag="-B$mold_dir"
  else
    mold_note="$mold_bin — trouvé, mais sans son shim $mold_dir/ld : activation manuelle"
  fi
fi

snippet() {
  local host
  host="$(rustc -vV | awk '/^host:/ {print $2}')"
  echo "# Machine-local build accelerators -- appended by scripts/local-toolchain.sh"
  echo "# of asterius-idp. Both are optional; neither belongs in a committed config."
  if [ -n "$sccache_bin" ]; then
    echo
    echo "[build]"
    echo "rustc-wrapper = \"$sccache_bin\""
  fi
  if [ -n "$mold_flag" ]; then
    echo
    echo "[target.$host]"
    echo "rustflags = [\"-C\", \"linker-features=-lld\", \"-C\", \"link-arg=$mold_flag\"]"
  fi
}

active_in_config() {
  [ -f "$USER_CONFIG" ] && grep -qE "^[[:space:]]*$1[[:space:]]*=" "$USER_CONFIG"
}

if [ "$PRINT_ONLY" = 1 ]; then
  if [ -z "$sccache_bin" ] && [ -z "$mold_flag" ]; then
    echo "# ni mold ni sccache sur cette machine : rien à ajouter." >&2
    exit 0
  fi
  snippet
  exit 0
fi

status() { printf '  %-8s %s\n' "$1" "$2"; }

echo "Accélérateurs locaux (config utilisateur : $USER_CONFIG)"

if [ -n "$mold_flag" ]; then
  if active_in_config rustflags; then
    status mold "$mold_bin — déjà référencé dans la config utilisateur"
  else
    status mold "$mold_bin — installé, pas activé"
  fi
elif [ -n "$mold_note" ]; then
  status mold "$mold_note"
else
  status mold "absent (paquet système ou release GitHub ; facultatif)"
fi

if [ -n "$sccache_bin" ]; then
  if active_in_config rustc-wrapper || [ -n "${RUSTC_WRAPPER:-}" ]; then
    status sccache "$sccache_bin — actif"
    sccache --show-stats 2>/dev/null | grep -E 'Cache hits|Cache size|Max cache size' | sed 's/^/           /'
  else
    status sccache "$sccache_bin — installé, pas activé"
  fi
else
  status sccache "absent (cargo install sccache ; facultatif)"
fi

if [ -n "$sccache_bin" ] || [ -n "$mold_flag" ]; then
  cat <<EOF

Pour activer, ajoute ceci à $USER_CONFIG :

$(snippet | sed 's/^./    &/')
EOF
  if [ -n "$sccache_bin" ]; then
    cat <<'EOF'
Et borne le cache à 20 Go dans ~/.config/sccache/config (sinon 10 Go par
défaut, et une variable d'environnement ne serait lue qu'au démarrage du
serveur sccache) :

    [cache.disk]
    dir = "~/.cache/sccache"
    size = 21474836480
EOF
  fi
fi
