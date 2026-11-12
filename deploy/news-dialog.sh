#!/usr/bin/env bash
# Confirm, edit or skip the RU/EN news draft for VERSION and send it with 'otter-admin announce' (D69).
# Usage: news-dialog.sh VERSION [--apk FILE --version-code N]
# The draft is dist/news/VERSION.md with the sections '## ru' and '## en'; edits made here are saved back to it.
source "$(dirname "$0")/lib.sh"
usage="usage: news-dialog.sh VERSION [--apk FILE --version-code N]"
version=${1:?$usage}; shift
apk="" code=""
while (( $# )); do case "$1" in
  --apk) apk=${2:?$usage}; shift 2 ;;
  --version-code) code=${2:?$usage}; shift 2 ;;
  *) die "$usage" ;;
esac; done
[[ -z "$apk" || -n "$code" ]] || die "--version-code required with --apk"
not_sent() { say "новость не отправлена"; exit 0; }
ask() { read -r -p "$1" "$2" || not_sent; }   # end of input = cancel
draft="$ROOT/dist/news/$version.md"
if [[ ! -f "$draft" ]]; then
  ask "Нет черновика $draft. Создать пустой? [y/N] " a
  [[ "$a" == [yYдД] ]] || not_sent
  mkdir -p "$(dirname "$draft")"
  printf '## ru\n\n## en\n' > "$draft"
  "${EDITOR:-nano}" "$draft"
fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
section() { awk -v want="## $1" '/^## / { on = ($0 == want); next } on' "$draft" | sed -e '/./,$!d'; }
args=()
for lang in ru en; do
  section "$lang" > "$tmp/$lang.txt"
  cp "$tmp/$lang.txt" "$tmp/$lang.orig"
  while true; do
    printf '\n---- %s ----\n' "$lang"; cat "$tmp/$lang.txt"; printf -- '-------------\n'
    if ! grep -q '[^[:space:]]' "$tmp/$lang.txt"; then say "пусто — пропускаю $lang"; break; fi
    ask "[о]тправить / [и]зменить / [п]ропустить: " c
    case "$c" in
      о|О|o|O) args+=("--$lang" "$tmp/$lang.txt"); break ;;
      и|И|e|E) "${EDITOR:-nano}" "$tmp/$lang.txt" ;;
      п|П|s|S|p|P) break ;;
    esac
  done
done
# keep edits in the draft, so a failed send or a later run starts from them
if ! cmp -s "$tmp/ru.txt" "$tmp/ru.orig" || ! cmp -s "$tmp/en.txt" "$tmp/en.orig"; then
  { printf '## ru\n'; cat "$tmp/ru.txt"; printf '\n## en\n'; cat "$tmp/en.txt"; } > "$draft"
  say "правки сохранены в $draft"
fi
(( ${#args[@]} )) || not_sent
if [[ -n "$apk" ]]; then args+=(--apk "$apk" --version-name "$version" --version-code "$code"); fi
ask "Отправить? [y/N] " a
[[ "$a" == [yYдД] ]] || not_sent
admin announce "${args[@]}"
