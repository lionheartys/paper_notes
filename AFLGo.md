# gen_distance_orig

这个脚本应该是用于获得目标项目中各个块到目标位置的距离。

```shell
if [ $# -lt 2 ]; then
  echo "Usage: $0 <binaries-directory> <temporary-directory> [fuzzer-name]"
  echo ""
  exit 1
fi

BINARIES=$(readlink -e $1)
TMPDIR=$(readlink -e $2)
AFLGO="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd )"
fuzzer=""
if [ $# -eq 3 ]; then
  fuzzer=$(find $BINARIES -maxdepth 1 -name "$3.0.0.*.bc" | rev | cut -d. -f5- | rev)
  if [ $(echo "$fuzzer" | wc -l) -ne 1 ]; then
    echo "Couldn't find bytecode for fuzzer $3 in folder $BINARIES."
    exit 1
  fi
fi

SCRIPT=$0
ARGS=$@
```

这是脚本开始的一些操作，其中第一步判断输入的参数个数是不是少于2个。

*$# 代表当前脚本接收到的参数的个数， -lt判断是否是小于*

然后用readlink命令检查传入的binaries-directory和temporary-directory是不是含有符号链接，如果有就将其解析为一个指向真正位置的绝对路径

之后找到存有AFLGO fuzzer的绝对路径

*BASH_SOURCE[0]是bash脚本中特有的一个变量，用来表示当前正在执行的脚本的绝对路径，然后用cd ... /../来进入脚本所在路径的父目录*

如果脚本的参数传入了fuzzer-name，那么就要查找在binaries-directory的目录下有没有存在命名形式为xxx.0.0.*.bc这样的bc文件，如果没有找到，则直接退出脚本的执行。

*find命令会提取到一个完整的绝对路径，但是需要的是不含这个bc文件名的路径，所以这里用cut命令将.作为分隔符（-d.），从第五个字段开始到行尾（-f5-）*



然后是进行一些检查和赋值：

```shell
SCRIPT=$0
ARGS=$@

#SANITY CHECKS
if [ -z "$BINARIES" ]; then echo "Couldn't find binaries folder ($1)."; exit 1; fi
if ! [ -d "$BINARIES" ]; then echo "No directory: $BINARIES."; exit 1; fi
if [ -z "$TMPDIR" ]; then echo "Couldn't find temporary directory ($3)."; exit 1; fi

binaries=$(find $BINARIES -maxdepth 1 -name "*.0.0.*.bc" | rev | cut -d. -f5- | rev)
if [ -z "$binaries" ]; then echo "Couldn't find any binaries in folder $BINARIES."; exit; fi

if [ -z $(which python) ] && [ -z $(which python3) ]; then echo "Please install Python"; exit 1; fi
#if python -c "import pydotplus"; then echo "Install python package: pydotplus (sudo pip install pydotplus)"; exit 1; fi
#if python -c "import pydotplus; import networkx"; then echo "Install python package: networkx (sudo pip install networkx)"; exit 1; fi

FAIL=0
STEP=1

RESUME=$(if [ -f $TMPDIR/state ]; then cat $TMPDIR/state; else echo 0; fi)

function next_step {
  echo $STEP > $TMPDIR/state
  if [ $FAIL -ne 0 ]; then
    tail -n30 $TMPDIR/step${STEP}.log
    echo "-- Problem in Step $STEP of generating $OUT!"
    echo "-- You can resume by executing:"
    echo "$ $SCRIPT $ARGS $TMPDIR"
    exit 1
  fi
  STEP=$((STEP + 1))
}

```

首先检查BINARIES（也就是参数1）有没有正常传入，然后检查这个BINARIES是不是一个目录（脚本会自动从目录下检索有没有对应的目标bc文件），最后检查用来存放一些过程中文件的临时文件夹有没有创建成功。

在检查完这些文件路径后就在BINARIES目录下搜索是否存在* .0.0.*.bc这样的bc文件（这里感觉是在AFLGO下按照作者给出的gold这一块的编译方式才能做出来的，因为当前很多方法生成的bc文件不叫这个名字）。

检查系统中有没有安装python3

设置了两个检查位FAIL和STEP

RESUME用于检查TMPDIR下stat文件的状态

下面设置了一个函数next_step，这个函数会检查当前脚本的核心逻辑执行是否出错，如果没有出错，将STEP对应数字加1输入到stat文件当中；如果出错了，则打印TEMP文件夹下对应步骤的日志中的最后30行并回显给用户。

## Construct control flow graph and call graph

下面脚本就进入了构建CFG和CG的过程。

```shell
if [ $RESUME -le $STEP ]; then

  cd $TMPDIR/dot-files

  if [ -z "$fuzzer" ]; then
    for binary in $(echo "$binaries"); do

      echo "($STEP) Constructing CG for $binary.."
      prefix="$TMPDIR/dot-files/$(basename $binary)"
      while ! opt -dot-callgraph $binary.0.0.*.bc -callgraph-dot-filename-prefix $prefix >/dev/null 2> $TMPDIR/step${STEP}.log ; do
        echo -e "\e[93;1m[!]\e[0m Could not generate call graph. Repeating.."
      done

      #Remove repeated lines and rename
      awk '!a[$0]++' $(basename $binary).callgraph.dot > callgraph.$(basename $binary).dot
      rm $(basename $binary).callgraph.dot
    done

    #Integrate several call graphs into one
    $AFLGO/distance/distance_calculator/merge_callgraphs.py -o callgraph.dot $(ls callgraph.*)
    echo "($STEP) Integrating several call graphs into one."

  else

    echo "($STEP) Constructing CG for $fuzzer.."
    prefix="$TMPDIR/dot-files/$(basename $fuzzer)"
    while ! opt -dot-callgraph $fuzzer.0.0.*.bc -callgraph-dot-filename-prefix $prefix >/dev/null 2> $TMPDIR/step${STEP}.log ; do
      echo -e "\e[93;1m[!]\e[0m Could not generate call graph. Repeating.."
    done

    #Remove repeated lines and rename
    awk '!a[$0]++' $(basename $fuzzer).callgraph.dot > callgraph.dot
    rm $(basename $fuzzer).callgraph.dot

  fi
fi
next_step
```

tips：注释里面虽然写的是构筑CG和CFG，但实际操作上是只有

这里首先遍历前面在binaries中获得的所以的bc文件的名称，对于每一个bc文件都使用opt（LLVM官方工具）来生成这个模块的CG。

对于输出的CG进行一次去重清洗

*使用awk '!a[$0]++'进行的简单去重清洗*

然后将各个模块生成的.dot文件传给merge_callgraphs.py这个程序将其合成为一个CG

## Generate config file keeping distance information for code instrumentation

这个阶段就是对CG中的距离进行计算，并进一步的计算CFG中基本块的距离

```shell
#-------------------------------------------------------------------------------
# Generate config file keeping distance information for code instrumentation
#-------------------------------------------------------------------------------
if [ $RESUME -le $STEP ]; then
  echo "($STEP) Computing distance for call graph .."

  $AFLGO/distance/distance_calculator/distance.py -d $TMPDIR/dot-files/callgraph.dot -t $TMPDIR/Ftargets.txt -n $TMPDIR/Fnames.txt -o $TMPDIR/distance.callgraph.txt > $TMPDIR/step${STEP}.log 2>&1 || FAIL=1

  if [ $(cat $TMPDIR/distance.callgraph.txt | wc -l) -eq 0 ]; then
    FAIL=1
    next_step
  fi

  printf "($STEP) Computing distance for control-flow graphs "
  for f in $(ls -1d $TMPDIR/dot-files/cfg.*.dot); do

    # Skip CFGs of functions we are not calling
    if ! grep "$(basename $f | cut -d. -f2)" $TMPDIR/dot-files/callgraph.dot >/dev/null; then
      printf "\nSkipping $f..\n"
      continue
    fi

    #Clean up duplicate lines and \" in labels (bug in Pydotplus)
    awk '!a[$0]++' $f > ${f}.smaller.dot
    mv $f $f.bigger.dot
    mv $f.smaller.dot $f
    sed -i s/\\\\\"//g $f
    sed -i 's/\[.\"]//g' $f
    sed -i 's/\(^\s*[0-9a-zA-Z_]*\):[a-zA-Z0-9]*\( -> \)/\1\2/g' $f

    #Compute distance
    printf "\nComputing distance for $f..\n"
    $AFLGO/distance/distance_calculator/distance.py -d $f -t $TMPDIR/BBtargets.txt -n $TMPDIR/BBnames.txt -s $TMPDIR/BBcalls.txt -c $TMPDIR/distance.callgraph.txt -o ${f}.distances.txt >> $TMPDIR/step${STEP}.log 2>&1 #|| FAIL=1
    if [ $? -ne 0 ]; then
      echo -e "\e[93;1m[!]\e[0m Could not calculate distance for $f."
    fi
    #if [ $FAIL -eq 1 ]; then
    #  next_step #Fail asap.
    #fi
  done
  echo ""

  cat $TMPDIR/dot-files/*.distances.txt > $TMPDIR/distance.cfg.txt

fi
next_step
```

首先就是使用distance.py这个程序对前面得到的整体的CG进行距离计算。会生成一个distance.callgraph.txt的文件，其中存储的就是CG中的函数间距离

然后对于之前生成的所有的函数的dot文件，CFG级别的距离计算。

在CFG的计算之中，首先看正在执行距离计算的函数在CG中有没有出现，如果没有出现，就直接跳过这次计算

然后清理原函数dot文件中的一些东西来修复格式，清理掉 `.dot` 文件中：

- 重复行
- 转义字符 `\"`
- 非标准标签（一些 LLVM/Graphviz 版本生成的 bug）

之后就对这个函数的dot执行基本块间的距离计算。

在完成对所有函数的BB距离计算后将保存的所有的distance文件集合为一个distance.cfg.txt文件。



