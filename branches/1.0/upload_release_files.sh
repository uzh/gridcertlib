#! /bin/sh
#
PROG="$(basename $0)"

usage () {
cat <<EOF
Usage: $PROG [options]

Upload files to http://gridcertlib.googlecode.com/files
Files to upload are searched for in the "target/" directory;
any "*.jar"/"*.tar.gz"/"*.zip" file is uploaded.

The release number, file type and contents (binary, javadoc, sources)
are automatically used as labels.

This program assumes that the script "googlecode_upload.py" is
available on your PATH. You can get this script from:
http://support.googlecode.com/svn/trunk/scripts/googlecode_upload.py

Options:

  -h, --help    Print this help text.
  -n, --no-act  Print upload commands instead of executing them.

Any other option given on the command line is passed down to the
"googlecode_upload.py" script.

EOF
}


## defaults

# GoogleCode project name
PROJECT='gridcertlib'

# space-separated list of labels to add to *any* file upload
LABELS="$PROJECT"

# name of the uploader script
googlecode_upload='googlecode_upload.py'


## helper functions

add_to_labels () {
    if [ -z "$LABELS" ]; then
        LABELS="$1"
    else
        LABELS="$LABELS,$1"
    fi
}

# TRUE if $1 contains $2 as a substring
contains () {
    echo "$1" | fgrep -q -e "$2"
}

die () {
  rc="$1"
  shift
  (echo -n "$PROG: ERROR: ";
      if [ $# -gt 0 ]; then echo "$@"; else cat; fi) 1>&2
  exit $rc
}

# TRUE if $1 ends with (literal) string $2
endswith () {
    expr "$1" : ".*$2\$" 1>/dev/null 2>&1
}

have_command () {
  type "$1" >/dev/null 2>/dev/null
}

require_command () {
  if ! have_command "$1"; then
    die 1 "Could not find required command '$1' in system PATH. Aborting."
  fi
}

is_absolute_path () {
    expr match "$1" '/' >/dev/null 2>/dev/null
}


## sanity check

require_command googlecode_upload.py


## parse command-line 

MAYBE=''
args=''

while [ $# -gt 0 ]; do
    case "$1" in
        --help|-h) 
            usage
            exit 0 
            ;;
        --labels*|-l) 
            # did we get '--labels=x,y,z' ?
            labels=$(echo "$1" | cut -d= -f2)
            if [ -z "$labels" ]; then
                # no, it's '--labels x,y,z'
                shift
                labels="$1"
            fi
            add_to_labels "$labels"
            ;;
        --no-act|--dry-run|-n)
            MAYBE=echo
            ;;
        --) 
            shift
            break
            ;;
        *)
            args="$args '$1'"
            ;;
    esac
    shift
done

## main

common_labels="$LABELS"
for path in $(ls target/${PROJECT}-* 2>/dev/null); do
    LABELS="$common_labels"
    summary=''

    filename=$(basename "$path")

    release=$(echo $filename | egrep --only-matching '[0-9]+(\.[0-9]+)+')
    add_to_labels $release

    if contains "$filename" '-bin.'; then
        summary="Package combining JAR files of compiled classes, source files and documentation"
    elif contains "$filename" '-sources.' || contains "$filename" '-src.'; then
        summary="Source files of ${PROJECT} ${release}"
    elif contains "$filename" '-javadoc.'; then
        summary="API documentation of ${PROJECT} ${release}"
    fi

    if endswith "$filename" '.asc'; then
        summary="PGP/GPG signature for file ${filename}"
        add_to_labels "pgp,gpg,signature"
    elif endswith "$filename"  '.jar'; then
        add_to_labels 'jar'
    elif endswith "$filename" '.tar.gz'; then
        add_to_labels 'tar,gzip'
    elif endswith "$filename" '.tar.bz2'; then
        add_to_labels 'tar.bzip2'
    elif endswith "$filename" '.zip'; then
        add_to_labels 'zip'
    fi

    if [ -z "$summary" ]; then
        echo 1>&2 "Could not deduce a description for '$filename': skipping it." 
    else
        eval $MAYBE $googlecode_upload "--project='$PROJECT'" "--labels='$LABELS'" "--summary='$summary'" $args "'$path'"
    fi
done


