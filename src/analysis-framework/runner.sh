#!/bin/bash

function help
{
    echo "Usage: runner.sh [ -p | --path ]
                 [ -d | --dlls ]
                 [ -b | --bits ]
                 [ -s | --stats ]
                 [ -e | --pickles ]
    [ -h | --help ]"
    exit 2
}

function progressbar
{
    printf "\e[A\e[K"
    
    let _progress=(${1}*100/${2}*100)/100
    let _done=(${_progress}*4)/10
    let _left=40-$_done
    
    _dll=${3}
    
    _fill=$(printf "%${_done}s")
    _empty=$(printf "%${_left}s")
    
    printf "Progress : [${_fill// /▇}${_empty// / }] ${_progress}%% Analyzing: ${_dll}\n"
}

SHORT=p:,d:,b:,h,s,e
LONG=path:,dlls:,bits:,help,stats,pickles
OPTS=$(getopt -a -n runner.sh --options $SHORT --longoptions $LONG -- "$@")

eval set -- "$OPTS"

stats=0
pickles=0

while :
do
    case "$1" in
        -p | --path )
            path="$2"
            shift 2
        ;;
        -d | --dlls )
            dlls="$2"
            shift 2
        ;;
        -b | --bits )
            bits="$2"
            shift 2
        ;;
        -h | --help)
            help
        ;;
        -s | --stats)
            stats=1
            shift 1
        ;;
        -e | --pickles)
            pickles=1
            shift 1
        ;;
        --)
            shift;
            break
        ;;
        *)
            echo "Unexpected option: $1"
            help
        ;;
    esac
done

if [ -z "$path" ] || [ -z "$dlls" ] || [ -z "$bits" ]; then
    help
fi

dlls_list="$(find $dlls -depth -maxdepth 1 -name "*.dll" -printf "%f\n")"
rm -rf $dlls/*.dll.*

if [ $pickles -eq 1 ]; then
    echo ""
    if [ -d "$dlls/pickles" ]; then
        rm -rf $dlls/pickles/
        rm -rf $dlls/logs/
    fi
    mkdir $dlls/pickles/
    mkdir $dlls/logs/
    
    total="$(ls -l $dlls/*.dll | wc -l)"
    iter=0
    for dll in $dlls_list; do
        progressbar $iter $total "Computing pickle: $dll"
        python $path/IDADRIVER.py --path $path --dll $dlls/$dll --bits $bits --out $dlls/pickles/$dll.pickle --log $dlls/logs/$dll.log;
        ((iter+=1))
    done
    progressbar $iter $total "Computing pickles: Completed"
fi

if [ $stats -eq 1 ]; then
    echo ""
    if [ -d "$dlls/stats" ]; then
        rm -rf $dlls/stats/
        rm -rf $dlls/analyzed/
    fi
    mkdir $dlls/stats/
    mkdir $dlls/analyzed/
    
    total="$(ls -l $dlls/*.dll | wc -l)"
    iter=0
    for dll in $dlls_list; do
        progressbar $iter $total "Computing stats: $dll"
        python $path/toxotidae.py --dll $dlls/pickles/$dll.pickle --out $dlls/analyzed/$dll.pickle > $dlls/stats/$dll.json;
        ((iter+=1))
    done
    progressbar $iter $total "Computing stats: Completed"
fi
