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

tips：注释里面虽然写的是构筑CG和CFG，但实际操作上是只有构筑CG

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



从上面这个生成距离的脚本中可以看到，在生成距离时，需要这样一些文件和程序:

1. 目标项目通过gold插件和LTO编译选项生成的，各个模块的bc文件（也就是形如.0.0.*.bc这样的）
2. llvm工具链中的opt优化器生成各个模块的CG，再由merge_callgraph.py合成为一个CG图
3. 在aflgo-clang编译过程中生成的BBcalls和BBnames这两个静态分析的结果文件
4. 最后生成实际的距离文件需要distance.py这个程序来分析

按照前面提到的这些文件，按照这样顺序，首先分析一下在第一次编译时选择的编译选项，来看它具体选择了些什么操作

# 第一次编译的编译选项

通过AFLGO开源仓库中给出的examples的构建流程来看，第一次编译时设置的编译选项是：

```shell
export TMP_DIR=$PWD/obj-aflgo/temp
export CC=$AFLGO/instrument/aflgo-clang; export CXX=$AFLGO/instrument/aflgo-clang++
export LDFLAGS=-lpthread
export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
```

设置的这几个环境变量都是编译相关的：TMP_DIR是存放编译过程生成的过程文件的，诸如BBnames和BBcall这两个非常重要的中间文件也是放在这个文件夹下的，以及后需要生成CG所需要的dot文件也是放在这个文件夹下的dot-files文件夹下的。

然后是对特定的目标项目编译选项的设置，这里的example是cxxfilt，给configure文件设置的编译选项为：

```
-DFORTIFY_SOURCE=2 -fstack-protector-all -fno-omit-frame-pointer -g -Wno-error $ADDITIONAL
```

可以看到这多出来的一些编译选项都是一些关于内存保护上的选项，比如fstack-protector-all就是在所有栈上生成canary，fno-omit-frame-pointer就是保留栈帧指针，-g是保留调试信息，-Wno-error是将warning保持为warning，防止编译器将其转化为报错。

# 尝试生成中间文件

这里可以用用example中的目标项目尝试生成一下中间的BBname和BBcalls文件来看一下它们的具体内容是什么。



# merge_callgraph.py

这个程序的逻辑非常简单：

```python
#!/usr/bin/env python3

import argparse
import networkx as nx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--out', type=str, required=True, help="Path to output dot file.")
    parser.add_argument('dot', nargs='+', help="Path to input dot files.")

    args = parser.parse_args()

    G = nx.DiGraph()
    for dot in args.dot:
        G.update(nx.DiGraph(nx.drawing.nx_pydot.read_dot(dot)))

    with open(args.out, 'w') as f:
        nx.drawing.nx_pydot.write_dot(G, f)


# Main function
if __name__ == '__main__':
    main()

```

它的逻辑就是将输入的所有.dot文件放入一张图中，然后将这张图输出位一个单独的文件

# aflgo-clang

这是aflgo包装后的clang，里面进行了一些处理（或者说是包装）来构建对应的编译命令

首先从main函数入手看一下：

```c
int main(int argc, char** argv) {

  if (isatty(2) && !getenv("AFL_QUIET")) {

#ifdef USE_TRACE_PC
    SAYF(cCYA "aflgo-compiler (yeah!) [tpcg] " cBRI VERSION  cRST "\n");
#else
    SAYF(cCYA "aflgo-compiler (yeah!) " cBRI VERSION  cRST "\n");
#endif /* ^USE_TRACE_PC */

  }

  if (argc < 2) {

    SAYF("\n"
         "This is a helper application for aflgo. It serves as a drop-in replacement\n"
         "for clang, letting you recompile third-party code with the required runtime\n"
         "instrumentation. A common use pattern would be one of the following:\n\n"

         "  CC=aflgo-clang ./configure\n"
         "  CXX=aflgo-clang++ ./configure\n\n"

         "In contrast to the traditional afl-clang tool, this version is implemented as\n"
         "an LLVM pass and tends to offer improved performance with slow programs.\n\n"

         "You can specify custom next-stage toolchain via AFL_CC and AFL_CXX. Setting\n"
         "AFL_HARDEN enables hardening optimizations in the compiled code.\n\n");

    exit(1);

  }


  find_obj(argv[0]);

  edit_params(argc, argv);

  execvp(cc_params[0], (char**)cc_params);

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}
```

首先检查stderr是不是默认绑定到了终端上，决定信息的打印模式。

然后检查一下传入的参数是不是小于2个，如果小于2，则程序直接退出，之后给用户打印一串帮助信息教用户怎么用。

之后就进入了主要的操作流程，首先是这个find_obj函数：

```c
static void find_obj(u8* argv0) {

  u8 *afl_path = getenv("AFLGO");
  u8 *slash, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/instrument/aflgo-runtime.o", afl_path);

    if (!access(tmp, R_OK)) {
      obj_path = alloc_printf("%s/instrument", afl_path);
      ck_free(tmp);
      return;
    }

    ck_free(tmp);

  }

  slash = strrchr(argv0, '/');

  if (slash) {

    u8 *dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

    tmp = alloc_printf("%s/aflgo-runtime.o", dir);

    if (!access(tmp, R_OK)) {
      obj_path = dir;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);
    ck_free(dir);

  }

  FATAL("Unable to find 'aflgo-runtime.o' or 'aflgo-pass.so'.");
 
}
```

函数中首先检查对应路径下是否存在aflgo-runtime.o这个文件，然后判断是否有权限访问这个文件，若不存在或无法访问则退出执行。

然后进入edit_params这个函数：

这个函数看起来非常长，但其实他的核心逻辑就是给传入的参数进行处理，然后传递给真正的clang进行编译：

```c
  name = strrchr(argv[0], '/');
  if (!name) name = argv[0]; else name++;

  if (!strcmp(name, "afl-clang-fast++") ||
      !strcmp(name, "aflgo-clang++"))
  {
    u8* alt_cxx = getenv("AFL_CXX");
    cc_params[0] = alt_cxx ? alt_cxx : (u8*)"clang++";
  } else {
    u8* alt_cc = getenv("AFL_CC");
    cc_params[0] = alt_cc ? alt_cc : (u8*)"clang";
  }
```

这一段是判断当前使用的是clang++还是clang，将编译命令的第一个参数（也就是对应的编译器）进行设置

下一段编译选项处理是：

```c
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] = "-load";
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] = alloc_printf("%s/aflgo-pass.so", obj_path);
```

这一段是在给clang传入自定义的pass，他实际上的命令就是：

```
-Xclang -load -Xclang /路径/aflgo-pass.so
```

这个-Xclang参数的意义就是将后面接的选项原封不懂的传入给clang，-load选项的意义就是加载一个LLVM插件（一般是pass）

```c
  cc_params[cc_par_cnt++] = "-Qunused-arguments";

  /* Detect stray -v calls from ./configure scripts. */

  if (argc == 1 && !strcmp(argv[1], "-v")) maybe_linking = 0;
```

这一段给参数加上-Qunused-arguments选项，这个选项的意思是让编译器不要因为某些参数“没有被使用”而报错（对应前面加载pass的操作，编译器可能会认为这个pass没有被使用而报错）

然后通过字符匹配看用户传入的原始参数中存不存在-v这个参数（这个参数一般是打印版本信息），如果存在，就将一个标志位maybe_linking置为0

```c
  while (--argc) {
    u8* cur = *(++argv);

    if (!strncmp(cur, "-distance", 9)
        || !strncmp(cur, "-targets", 8)
        || !strncmp(cur, "-outdir", 7))
      cc_params[cc_par_cnt++] = "-mllvm";

    if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;

    if (!strcmp(cur, "-x")) x_set = 1;

    if (!strcmp(cur, "-c") || !strcmp(cur, "-S") || !strcmp(cur, "-E"))
      maybe_linking = 0;

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    if (!strcmp(cur, "-shared")) maybe_linking = 0;

    if (!strcmp(cur, "-Wl,-z,defs") ||
        !strcmp(cur, "-Wl,--no-undefined")) continue;

    cc_params[cc_par_cnt++] = cur;

  }

```

这个while循环逐个读取用户输入的原始编译命令中的选项，如果存在某些选项，则设置一些标志位进行处理。

检查原始命令中是否存在-distance -targets -outdir这几个参数，如果存在其中一个，则在包装的命令中加入-mllvm这个选项。

-mllvm这个参数的意义是将后面的参数直接原封不动的传入给编译器后端（也就是前面传入的那个pass）进行处理，诸如distance这些参数clang本身是识别为无意义的，因为他并不是一个标准的选项。

```c
    if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;
```

这一段是在设置目标架构的位数，同时设置标志位为对应的位数。

```c
if (!strcmp(cur, "-x")) x_set = 1;
```

这里检查是否设置了-x选项，这个选项用于显式的指定输入文件的语言类型（c c++ 汇编），如果有设置，则将x_set这个标志位置为1

```c
    if (!strcmp(cur, "-c") || !strcmp(cur, "-S") || !strcmp(cur, "-E"))
      maybe_linking = 0;
```

这里判断原始的编译选项中是否存在-c -S -E 这三个选项。

-c表示将目标编译为目标文件（.o）但不链接

-S表示将目标编译为汇编文件（.s）但不链接

-E表示将目标文件进行预处理，结果打印到标准输出，不进行编译也不链接

这三个操作都是典型的非链接操作，所以将maybe_linking标志位设定为1

```c
    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1;
```

这里判断原始选项中是否开启了ASAN和MSAN，并设置标志位asan_set

```c
if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;
```

这里判断原始选项中是否出现了FORTIFY_SOURCE这个编译选项。

这个选项是目标程序中对一些标准的C库函数（strcpy`, `sprintf`, `memcpy等）开启安全增强的选项，*这个选项比较特殊，它是通过宏定义开启的*

同时设置标志位fortify_set

```c
if (!strcmp(cur, "-shared")) maybe_linking = 0;
```

这里判断原始选项中是否有-share选项。

这个选项是将目标编译为动态链接库（.so）文件，他没有标准的main函数入口，所以这里也设置了一个maybe_linking标志位为0（把生成.so文件也是做是非标准链接）

```c
    if (!strcmp(cur, "-Wl,-z,defs") ||
        !strcmp(cur, "-Wl,--no-undefined")) continue;
```

这里判断原始的选项中是否出现了-Wl,-z,defs -Wl,--no-undefined这些选项，如果有，则直接跳过，不将这些参数写入aflgo编译的选项中。

*这些选项一般用于动态链接库生成时避免报错，它会要求当前目标中所有的符号解析在链接时都必须有定义，但是在aflgo的编译过程中，有一些符号是在最终链接阶段才会插入的（依赖于一些运行时操作），保留这个选项可能会导致报错*

```c
cc_params[cc_par_cnt++] = cur;
```

将经过处理后的原始选项保存入aflgo 的编译选项中。

```c
  if (getenv("AFL_HARDEN")) {

    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set)
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";

  }
```

这一段检查是否有设置环境变量AFL_HARDEN，如果有，则添加-fstack-protector-all选项

这个选项是在所有位置上开启堆栈保护（如canary等）

再看fortify_set标志位（也就是前面进行验证的FORTIFY_SOURCE的编译选项有没有被打开），如果原本目标中没有开启FORTIFY_SOURCE这个编译选项，那么则在这里加上-D_FORTIFY_SOURCE=2这个编译选项。

```c
  if (!asan_set) {

    if (getenv("AFL_USE_ASAN")) {

      if (getenv("AFL_USE_MSAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("ASAN and AFL_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=address";

    } else if (getenv("AFL_USE_MSAN")) {

      if (getenv("AFL_USE_ASAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("MSAN and AFL_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=memory";

    }

  }

```

这一段是在根据asan_set（消杀器是否开启）标志位进行操作，主要是看原始的选项中有没有开启ASAN或MSAN，如果开启了ASAN则禁止MSAN和FORTIFY_SOURCE（这几个编译选项是互斥的）

```c
  if (!getenv("AFL_DONT_OPTIMIZE")) {

    cc_params[cc_par_cnt++] = "-g";
    // cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";

  }
```

这个部分是在检查是否设置了AFL_DONT_OPTIMIZE这个环境变量，如果没有设置了这个环境变量，在编译命令中加入-g和-funroll-loops编译选项。

-g选项是保留调试信息

-funroll-loops选项是一个针对于循环展开的优化选项，是编译器通过一些机制对循环语句进行展开，将其转化一些可以并行计算的语句

```c
  if (getenv("AFL_NO_BUILTIN")) {

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";

  }
```

这一段检查是否设置了AFL_NO_BUILTIN这个环境变量，如果有设置，那么就在编译选项中加入-fno-builtin-strcmp等选项。

这些看起来比较相似的选项是禁止编译器对一些常用的C标准库函数进行优化，将其替换为优化版本和内建版本（Builtin）

```c
  cc_params[cc_par_cnt++] = "-D__AFL_HAVE_MANUAL_CONTROL=1";
  cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
  cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";

  /* When the user tries to use persistent or deferred forkserver modes by
     appending a single line to the program, we want to reliably inject a
     signature into the binary (to be picked up by afl-fuzz) and we want
     to call a function from the runtime .o file. This is unnecessarily
     painful for three reasons:

     1) We need to convince the compiler not to optimize out the signature.
        This is done with __attribute__((used)).

     2) We need to convince the linker, when called with -Wl,--gc-sections,
        not to do the same. This is done by forcing an assignment to a
        'volatile' pointer.

     3) We need to declare __afl_persistent_loop() in the global namespace,
        but doing this within a method in a class is hard - :: and extern "C"
        are forbidden and __attribute__((alias(...))) doesn't work. Hence the
        __asm__ aliasing trick.

   */

  cc_params[cc_par_cnt++] = "-D__AFL_LOOP(_A)="
    "({ static volatile char *_B __attribute__((used)); "
    " _B = (char*)\"" PERSIST_SIG "\"; "
#ifdef __APPLE__
    "__attribute__((visibility(\"default\"))) "
    "int _L(unsigned int) __asm__(\"___afl_persistent_loop\"); "
#else
    "__attribute__((visibility(\"default\"))) "
    "int _L(unsigned int) __asm__(\"__afl_persistent_loop\"); "
#endif /* ^__APPLE__ */
    "_L(_A); })";

  cc_params[cc_par_cnt++] = "-D__AFL_INIT()="
    "do { static volatile char *_A __attribute__((used)); "
    " _A = (char*)\"" DEFER_SIG "\"; "
#ifdef __APPLE__
    "__attribute__((visibility(\"default\"))) "
    "void _I(void) __asm__(\"___afl_manual_init\"); "
#else
    "__attribute__((visibility(\"default\"))) "
    "void _I(void) __asm__(\"__afl_manual_init\"); "
#endif /* ^__APPLE__ */
    "_I(); } while (0)";

```

这一部分首先添加了几个宏定义：

```
-D__AFL_HAVE_MANUAL_CONTROL=1
-D__AFL_COMPILER=1
-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1
```

这些编译选项并非是控制编译器的，而是用于添加到被编译目标文件的开头，作为：

```c
#define __AFL_HAVE_MANUAL_CONTROL 1
```

后面的这段注释是作者在解释实现AFL的persistent和deferred模式遇到的一些问题和他的为了解决这些问题而采取的措施。这里可以看出作者对LLVM编译器有很深入的了解。

后面的这些编译选项设置就是作者通过结合runtime库来完成的persistent和deferred模式的实现:

```c
  cc_params[cc_par_cnt++] = "-D__AFL_LOOP(_A)="
    "({ static volatile char *_B __attribute__((used)); "
    " _B = (char*)\"" PERSIST_SIG "\"; "
```

这里向目标程序插入了一个字符串SIG_AFL_PERSIST，并使用volatile和__ attribute__来防止编译器将它优化掉：

```c
static volatile char *_B __attribute__((used)) = "##SIG_AFL_PERSIST##";
```

这个字符串是AFL在后续操作中识别对象是否开启persistent模式的标志。

这里说一下有关于这个persistent模式和deferred模式：

在传统的AFL forkserver机制中，目标程序是执行一次fuzz就会有一次fork

## **persistent模式（持续化模式）：**

通过前面的宏定义的D__AFL_LOOP引入这个操作，在afl-llvm-rt.o这个runtime库中实现它的逻辑。用户只需要在程序中像这样调用一下这个宏就可以使用persistent模式了：

```
while (__AFL_LOOP(1000)) {

  /* Read input data. */
  /* Call library code to be fuzzed. */
  /* Reset state. */

}

/* Exit normally */
```

persistent模式的出现实质上是为了更进一步的消解fork进程产生的开销。使目标在一次fork中的同一个进程空间内对一个接口进行多次fuzz。

这其实是对Libfuzzer的一种借鉴和模仿。通俗的说，就是让目标程序在被fork一次之后在这次fork出的进程空间中执行若干次（传统的机制是fork一次就只执行一次）

## **deferred模式（forkserver 延迟启动）：**

通过前面的宏定义的-D__ AFL_HAVE_MANUAL_CONTROL=1来开启这个模式，然后通过在driver中手动的写入： __AFL_INIT()这个函数来显式的设定forkserver启动的时间。

这个模式存在的意义是在某些场景下，例如需要初始化数据库和需要建立大量网络连接的情况下，如果每次都在加载的最开始就设置启动forkserver，那么开销有时候是很大的，所以就可以通过这个模式来手动选择forkserver启动的位置。



最后的这部分：

```c
  if (maybe_linking) {

    if (x_set) {
      cc_params[cc_par_cnt++] = "-x";
      cc_params[cc_par_cnt++] = "none";
    }

    switch (bit_mode) {

      case 0:
        cc_params[cc_par_cnt++] = alloc_printf("%s/aflgo-runtime.o", obj_path);
        break;

      case 32:
        cc_params[cc_par_cnt++] = alloc_printf("%s/aflgo-runtime-32.o", obj_path);

        if (access(cc_params[cc_par_cnt - 1], R_OK))
          FATAL("-m32 is not supported by your compiler");

        break;

      case 64:
        cc_params[cc_par_cnt++] = alloc_printf("%s/aflgo-runtime-64.o", obj_path);

        if (access(cc_params[cc_par_cnt - 1], R_OK))
          FATAL("-m64 is not supported by your compiler");

        break;

    }

  }

  cc_params[cc_par_cnt] = NULL;
```

这里首先检查maybe_linking标志位有没有被设置，这个这个标志位代表目标文件可能是一个用于链接的文件。

然后检查x_set标志位，这个标志位表示当前的文件不是一个源码文件

最后通过bit_mode标志位设置当前需要链接的运行时库是哪个版本的。

# aflgo-runtime.o.c

在前面对aflgo-clang这个编译包装程序分析中，可以看到有这样一个部分：

```c
cc_params[cc_par_cnt++] = alloc_printf("%s/aflgo-runtime.o", obj_path);
```

这里就是在为编译器添加运行时库aflgo-runtime.o，这是一个非常重要的运行时库，它提供了一些aflgo在插桩和在运行过程中需要使用到的函数。下面就分析一下这个运行时库中的函数。

首先我们要知道的是，对于当前的fuzz工具，大部分已经是使用llvm来进行插桩和各种编译时操作了，而llvm的插桩与gcc有很大的不同。

gcc插桩一般是通过在汇编阶段向目标程序的汇编文件中写入插桩逻辑（也是一些汇编代码）来实现。

而llvm的pass则更加便利，它允许我们直接写高级语言来完成插桩逻辑，所以我们可以在运行时库中看到很多原本在afl-as中通过汇编实现的逻辑（诸如__afl_start_forkserver）

所以在这个地方就可以不用硬看汇编代码来理解插桩函数的逻辑，而是可以直接看高级语言编写而成的插桩逻辑：

## __afl_map_shm：

```c
static void __afl_map_shm(void) {

  u8 *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }

}
```

这个函数是用于初始化shm共享虚拟内存的，最关键的就是这个：

```c
__afl_area_ptr = shmat(shm_id, NULL, 0);
```

分配一块共享内存，然后将表示虚拟内存存在的标志位__afl_area_ptr置为1

## __afl_start_forkserver：

```c
static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;

  u8  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;
  
      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}
```

这个函数用于实现具体的forkserver逻辑。首先通过管道给forkserver发送一个四字节的信号，确定父进程存在，然后进入一个循环，通过管道从forkserver处读取开始的信号，如果读取成功则开始正式的fork操作。

在forkserver自检完成后就fork出一个子进程，fork出的子进程关闭与forkserver的通信管道（使程序能够正常运行，防止一些bug的出现），对于父进程则将刚刚fork出的子进程的pid通过通信管道返回给fuzzer后等待子进程执行完毕。

在这个函数中还有一个部分：

```c
    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }
```

这部分是为了解决竞态条件的问题，在persistent模式下，子进程执行完一次后会自动挂起，并等待下一次的执行，如果fuzzer设置了超时会发出终止信号，那么可能会与forkserver发出的继续信号产生竞态条件，所以这里会判断子进程是不是已经挂起了。如果在处于挂起且又收到了结束信号，那么就将这个子进程关闭。

## __afl_persistent_loop：

这个函数是用于实现persistent模式：

```c
int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE + 16);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}
```

首先判断进入这个函数执行的子进程是不是处于AFL_LOOP（persistent的循环次数）的第一次执行，如果是第一次执行那么要对存储AFL覆盖率的缓冲区进行清空，防止之前执行在其中残留有数据。然后将循环次数设定为用户指定的循环次数后就进入正常执行。

后面就是每次执行完成后主动发出一个SIGSTOP的挂起信号，在循环次数完结之后为了防止__afl_area_ptr指向的共享内存区域继续记录循环体之外代码的覆盖率，会将其指向一个dummy output region。

## __afl_manual_init：

```c
void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;

  }

}
```

这个函数是在deferred模式下用户选择手动启动forkserver时使用的，其实就是包装了初始化共享内存和启动forkserver的函数

## __afl_auto_init：

```c
/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}
```

这个函数就是正常模式下AFL自动化初始入口函数操作。如果设置了deferred模式，则不按照正常的初始化进行

*tips：这里用到了一个GNU C中的独有关键字attribute，它使用constructor参数时指定这个函数的执行优先级，这里设置为CONST_PRIO，也就是先于main函数之前执行。*

## SanitizerCoverage：

在LLVM中提供了一种更先进的插桩方式：Sanitizer Coverage，这个方法比传统的afl的插桩模式更简单也更精确。

当使用的-fsanitize-coverage=trace-pc-guard选项编译目标时，LLVM会自动的向其中的每条边插入一个结构：

```c
static uint32_t guard_var;
__sanitizer_cov_trace_pc_guard(&guard_var);
```

这个__sanitizer_cov_trace_pc_guard就对应这个回调函数：

```c
void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}
```

在每次执行到插桩点时就会执行这个函数，它的逻辑非常简单，就是将guard作为索引增加这条边的hit数

然后是__sanitizer_cov_trace_pc_guard_init这个函数，它在程序开始执行时调用一次：

```c
void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  u8* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}
```

首先判断start和stop是不是同一个位置防止重复初始化，然后通过环境变量设置插桩率（默认为100%全部插桩）

然后就是初始化所有边的ID：

```c
while (start < stop) {
  if (R(100) < inst_ratio)
    *start = R(MAP_SIZE - 1) + 1;
  else
    *start = 0;
  start++;
}
```

给每个边分配一个1~MAP_SIZE 的随机 ID，R(...)是个宏，表示取这个范围内的一个随机数，如果此处不插桩，则将其这里的ID置为0。

## AFLGO_TRACING

这一部分通过一个宏定义判断来决定是否需要执行，这些函数是用于aflgo在静态分析阶段记录基本块和这些基本块之间的距离。

### hashset族函数：

在这一部分有很多hashset开头的函数，这些函数主要是实现哈希集合数据结构。

首先是hashset_create函数，它用于实例化一个hashset结构体：

```c
    struct hashset_st {
        size_t nbits;
        size_t mask;

        size_t capacity;
        size_t *items;
        size_t nitems;
        size_t n_deleted_items;
    };

    typedef struct hashset_st *hashset_t;
```

hashset_num_items函数用于返回哈希集合中有多少个成员。

hashset_destroy函数用于销毁哈希集合并释放内存。

hashset_add_member函数用于向哈希集合中添加新成员。

maybe_rehash函数检查当前哈希集合的负载率，如果超过85%，则对其进行扩容。

hashset_add函数就是hashset_add_member与maybe_rehash的封装。

hashset_remove函数用于移除哈希集合中的一个成员。

hashset_is_member函数用于检查一个成员是否在哈希集合中。

### llvm_profiling_call：

这是最主要的记录逻辑：

```c
void llvm_profiling_call(const char* bbname)
	__attribute__((visibility("default")));

void llvm_profiling_call(const char* bbname) {
    if (filefd != NULL) {
        writeBB(bbname);
    } else if (getenv("AFLGO_PROFILER_FILE")) {
        filefd = fopen(getenv("AFLGO_PROFILER_FILE"), "a+");
        if (filefd != NULL) {
            strcpy(edgeStr, "START");
            edgeSet = hashset_create();
            fprintf(filefd, "--------------------------\n");
            writeBB(bbname);
        }
    }
}
```

首先判断是否打开了记录文件的描述符，没有的话就从AFLGO_PROFILER_FILE这个环境变量中获取，之后给edgeStr初始化一个START字符串并用实例化一个哈希集合。

然后执行writeBB函数记录基本块。

### writeBB：

这个函数是实际向文件中记录执行过的基本块名称：

```c
inline __attribute__((always_inline))
void writeBB(const char* bbname) {
    strcat(edgeStr, bbname);
    size_t cksum=(size_t)hash32(bbname, strlen(edgeStr), 0xa5b35705);
    if(!hashset_is_member(edgeSet,(void*)cksum)) {
        fprintf(filefd, "[BB]: %s\n", bbname);
        hashset_add(edgeSet, (void*)cksum);
    }
    strcpy(edgeStr, bbname);
    fflush(filefd);
}
```

首先将传入的BB名称拼接到全局变量edgeStr中（也就是前面说到的初始化了一个START字符串的那个），形成一个路径上下文（例如：STARTmain），然后将BB名称与这个路径上下文做一次哈希 ：

```c
size_t cksum=(size_t)hash32(bbname, strlen(edgeStr), 0xa5b35705);
```

判断这个成员是否已经存在于哈希集合中，如果没有则加入到哈希集合中（进行去重，防止多次记录），并将这个基本块的名称以如下形式记录到文件中：

```
[BB]:main
```

然后重置edgeStr变量使其中只有

当前的这个BB名称（最开始是START现在就是main了）

# aflgo-pass.so.cc

## 设置所需参数：

首先是对于pass需要的一些参数进行设置：

```c++
cl::opt<std::string> DistanceFile(
    "distance",
    cl::desc("Distance file containing the distance of each basic block to the provided targets."),
    cl::value_desc("filename")
);

cl::opt<std::string> TargetsFile(
    "targets",
    cl::desc("Input file containing the target lines of code."),
    cl::value_desc("targets"));

cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc("Output directory where Ftargets.txt, Fnames.txt, and BBnames.txt are generated."),
    cl::value_desc("outdir"));
```

这里的cl是llvm命名空间中的`llvm::cl` 的简写，给pass自定义`-targets`、`-distance`、`-outdir` 这几个选项。

可以看到这个pass需要输入一个包含了各个基本块到目标位置距离的文件、一个包含了目标程序中需要定向到目标位置在代码中的行号的文件、一个接受输出文件的路径。

## 特化DOT模板

LLVM的pass中提供了一个用于生成DOT文件的基类：DefaultDOTGraphTraits

aflgo生成DOT文件的逻辑就是从这个基类中进行一定的修改：

```c++
namespace llvm {

template<>
struct DOTGraphTraits<Function*> : public DefaultDOTGraphTraits {
  DOTGraphTraits(bool isSimple=true) : DefaultDOTGraphTraits(isSimple) {}

  static std::string getGraphName(Function *F) {
    return "CFG for '" + F->getName().str() + "' function";
  }

   std::string getNodeLabel(BasicBlock *Node, Function *Graph) {
    if (!Node->getName().empty()) {
      return Node->getName().str();
    }

    std::string Str;
    raw_string_ostream OS(Str); //raw_string_ostream是LLVM中的流封装，用于写入字符串缓冲区。

    Node->printAsOperand(OS, false);
    return OS.str();
  }
};

} 
```

首先是调用基类中的构造函数进行初始化，这里将isSimple默认设置为true

其中getGraphName是设置生成的DOT文件的图名，这里的命名规则就是：

```
"CFG for '" + F->getName().str() + "' function"
```

F->getName().str()就是获取当前函数的名称，返回值类似于`CFG for 'main' function`

之后的getNodeLabel就是设置图中节点（也就是每个基本块）的标签，如果这个基本块有名字，则直接将它的名字作为标签，如果没有，则打印该基本块的“操作数格式名”作为标签。

## AFLCoverage

之后再一个匿名命名空间中定义了一个AFLCoverage类：

```c++
namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}
```

这其实是一个模块级别（Module-level）Pass，它继承自ModulePass

对于这个成员ID，LLVM 的 `Pass` 系统要求每个 Pass 都有一个唯一的 `ID`，通过这个 ID 实现注册与识别。

调用父类的构造函数作为本身的构造函数。

runOnModule是pass的主入口，一般就是这个模块pass的核心逻辑，它在被pass manager调用时被执行，在这个pass中它的真实实现在后面会看到。

## getDebugLoc

这个函数与获取目标编译过程中产生的debug信息有关，主要功能是提取当前IR指令在源码中的对应行号位置

```c++
static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {
#ifdef LLVM_OLD_DEBUG_API
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown()) {
    DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
    DILocation oDILoc = cDILoc.getOrigLocation();

    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();

    if (filename.empty()) {
      Line = cDILoc.getLineNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
#endif /* LLVM_OLD_DEBUG_API */
}
```

前面ifdef中包裹的部分不用细究，这个是为了兼容老版本LLVM。主要的处理逻辑是首先通过DILocation *Loc = I->getDebugLoc()来尝试获取该条IR处的调试信息（如果有的话）提取出调试信息中的IR映射到源代码中的行号以及文件名（getLine和getFilename）

在对于没有提取到filename的情况，尝试获取getInlinedAt（这是一种经典情况，由于编译优化无法使内联函数等丢失调试信息）

## AFLCoverage::runOnModule

这是对前面namespace中AFLCoverage类中pass主入口函数runOnModule的重载具体实现，也是这个源文件中代码的主要部分。

首先是一些参数的校验与准备

```c++
  bool is_aflgo = false;
  bool is_aflgo_preprocessing = false;

  if (!TargetsFile.empty() && !DistanceFile.empty()) {
    FATAL("Cannot specify both '-targets' and '-distance'!");
    return false;
  }

  std::list<std::string> targets;
  std::map<std::string, int> bb_to_dis;
  std::vector<std::string> basic_blocks;

  if (!TargetsFile.empty()) {

    if (OutDirectory.empty()) {
      FATAL("Provide output directory '-outdir <directory>'");
      return false;
    }

    std::ifstream targetsfile(TargetsFile);
    std::string line;
    while (std::getline(targetsfile, line))
      targets.push_back(line);
    targetsfile.close();

    is_aflgo_preprocessing = true;

  } else if (!DistanceFile.empty()) {

    std::ifstream cf(DistanceFile);
    if (cf.is_open()) {

      std::string line;
      while (getline(cf, line)) {

        std::size_t pos = line.find(",");
        std::string bb_name = line.substr(0, pos);
        int bb_dis = (int) (100.0 * atof(line.substr(pos + 1, line.length()).c_str()));

        bb_to_dis.emplace(bb_name, bb_dis);
        basic_blocks.push_back(bb_name);

      }
      cf.close();

      is_aflgo = true;

    } else {
      FATAL("Unable to find %s.", DistanceFile.c_str());
      return false;
    }

  }

```

首先检查TargetsFile和DistanceFile以及OutDirectory这几个前面设置的命令行参数有没有正确传入对应的数据，并根据Targets和Distance参数的传入判断当前处于aflgo的模糊测试阶段还是预处理阶段（**这两个参数分别属于两个阶段的处理，不能并存**）。

之后定义了list(列表) map（哈希表） vector（向量）三个数据结构分别对应了目标、基本块到目标块距离、所有的基本块这几个关键的对象。

如果传入了target文件，打开targetsfile的文件流，将里面的目标位置信息读取到创建好的targets（list）对象中，设置is_aflgo_preprocessing为true，说明当前处于预处理阶段。

如果传入了distance文件，则与之前相同的，打开文件流，提取出其中基本块到目标位置的距离，按照一定的规则对内容进行划分。将距离值x100处理为int型（方便比较），将距离值与基本块名形成映射后放入前面设置的哈希表中，在这个过程中将基本块的名称同时存入vector。最后将is_aflgo设置为true，说明当前处于aflgo的距离插桩阶段。

```c++
  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    if (is_aflgo || is_aflgo_preprocessing)
      SAYF(cCYA "aflgo-llvm-pass (yeah!) " cBRI VERSION cRST " (%s mode)\n",
           (is_aflgo_preprocessing ? "preprocessing" : "distance instrumentation"));
    else
      SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");


  } else be_quiet = 1;
```

这个部分首先判断有没有设置AFL_QUIET（安静模式）环境变量，来决定是否输出一些相应的banner

```c++
  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Default: Not selective */
  char* is_selective_str = getenv("AFLGO_SELECTIVE");
  unsigned int is_selective = 0;

  if (is_selective_str && sscanf(is_selective_str, "%u", &is_selective) != 1)
    FATAL("Bad value of AFLGO_SELECTIVE (must be 0 or 1)");

  char* dinst_ratio_str = getenv("AFLGO_INST_RATIO");
  unsigned int dinst_ratio = 100;

  if (dinst_ratio_str) {

    if (sscanf(dinst_ratio_str, "%u", &dinst_ratio) != 1 || !dinst_ratio ||
        dinst_ratio > 100)
      FATAL("Bad value of AFLGO_INST_RATIO (must be between 1 and 100)");

  }
```

这个部分完成了插桩率的设置以及判断是否开启选择性插桩。

首先检查是否设置了AFL_INST_RATIO这个环境变量，这个环境变量是设置相应插桩率（也就是插桩部分的比率，一般都是默认的100）。

然后检查了AFLGO_SELECTIVE以及AFLGO_INST_RATIO这两个环境变量的设置，分别对应是否开启选择性插桩以及aflgo模式下的插桩率。

### 预处理阶段

这是aflgo预处理的实现逻辑，也就是由前面是否传入目标位置文件（targetfiles）决定是否进入这块操作。

```c++
  /* Instrument all the things! */

  int inst_blocks = 0;

  if (is_aflgo_preprocessing) {

    std::ofstream bbnames(OutDirectory + "/BBnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream bbcalls(OutDirectory + "/BBcalls.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream fnames(OutDirectory + "/Fnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream ftargets(OutDirectory + "/Ftargets.txt", std::ofstream::out | std::ofstream::app);

    /* Create dot-files directory */
    std::string dotfiles(OutDirectory + "/dot-files");
    if (sys::fs::create_directory(dotfiles)) {
      FATAL("Could not create directory %s.", dotfiles.c_str());
    }

    for (auto &F : M) {

      bool has_BBs = false;
      std::string funcName = F.getName().str();

      /* Black list of function names */
      if (isBlacklisted(&F)) {
        continue;
      }

      bool is_target = false;
      for (auto &BB : F) {

        std::string bb_name("");
        std::string filename;
        unsigned line;

        for (auto &I : BB) {
          getDebugLoc(&I, filename, line);

          /* Don't worry about external libs */
          static const std::string Xlibs("/usr/");
          if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
            continue;

          std::size_t found = filename.find_last_of("/\\");
          if (found != std::string::npos)
            filename = filename.substr(found + 1);

          if (bb_name.empty()) 
            bb_name = filename + ":" + std::to_string(line);
          
          if (!is_target) {
            for (auto &target : targets) {
              std::size_t found = target.find_last_of("/\\");
              if (found != std::string::npos)
                target = target.substr(found + 1);

              std::size_t pos = target.find_last_of(":");
              std::string target_file = target.substr(0, pos);
              unsigned int target_line = atoi(target.substr(pos + 1).c_str());

              if (!target_file.compare(filename) && target_line == line)
                is_target = true;

            }
          }

          if (auto *c = dyn_cast<CallInst>(&I)) {

            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            if (auto *CalledF = c->getCalledFunction()) {
              if (!isBlacklisted(CalledF))
                bbcalls << bb_name << "," << CalledF->getName().str() << "\n";
            }
          }
        }

        if (!bb_name.empty()) {

          BB.setName(bb_name + ":");
          if (!BB.hasName()) {
            std::string newname = bb_name + ":";
            Twine t(newname);
            SmallString<256> NameData;
            StringRef NameRef = t.toStringRef(NameData);
            MallocAllocator Allocator;
            BB.setValueName(ValueName::Create(NameRef, Allocator));
          }

          bbnames << BB.getName().str() << "\n";
          has_BBs = true;

#ifdef AFLGO_TRACING
          auto *TI = BB.getTerminator();
          IRBuilder<> Builder(TI);

          Value *bbnameVal = Builder.CreateGlobalStringPtr(bb_name);
          Type *Args[] = {
              Type::getInt8PtrTy(M.getContext()) //uint8_t* bb_name
          };
          FunctionType *FTy = FunctionType::get(Type::getVoidTy(M.getContext()), Args, false);
          Constant *instrumented = M.getOrInsertFunction("llvm_profiling_call", FTy);
          Builder.CreateCall(instrumented, {bbnameVal});
#endif

        }
      }

      if (has_BBs) {
        /* Print CFG */
        std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
        std::error_code EC;
        raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::F_None);
        if (!EC) {
          WriteGraph(cfgFile, &F, true);
        }

        if (is_target)
          ftargets << F.getName().str() << "\n";
        fnames << F.getName().str() << "\n";
      }
    }

  }
```

首先根据传入的OutDirectory参数打开BBnames.txt BBcalls.txt Fnames.txt Ftargets.txt这几个记录信息的文件。

同时创建一个用于存储dotfiles文件的临时目录：

```
std::string dotfiles(OutDirectory + "/dot-files");
```

遍历模块中的所有函数：

```
for (auto &F : M)
```

获取这些函数的名称（如果有的话），并跳过之前设置的黑名单中的函数。

然后对于每个函数，遍历其中所有的基本块：

```
 for (auto &BB : F) 
```

对于每个基本块再遍历其中的每一条IR指令：

```
for (auto &I : BB)
```

*tips：	这里获取基本块及IR指令的方法都是使用LLVM来自动完成，这也是现在fuzz插桩多用LLVM而不是从汇编中直接插入代码的原因之一*

前面分析过了有一个getDebugLoc函数用于获取每条IR指令所在源码的行数和文件名，也就是用在这里。

在获取了每条IR指令对应的文件名和所在行号之后，根据文件名的开头是否存在`/usr/`来判断是否是用户的系统库代码，如果是的话则跳过。

对于前面没有成功获取到基本块名的那些基本块，在这里将获取到的指令所在文件名进行处理后（去除路径信息只保留文件名）加上行号作为这个基本块的名称：

```
bb_name = filename + ":" + std::to_string(line);
```

之后将获取到的文件名和行号与用户传入的目标文件中的目标文件和目标行号进行比对判断该指令是否处于基本块内，如果是的话则将is_target设置为true。

然后判断当前指令是不是一个函数调用指令：

```
auto *c = dyn_cast<CallInst>(&I)
```

其中的dyn_cast是LLVM中独有的实现”向下类型转换“的机制，I 原本是Instruction类，而CallInst是继承了Instruction的一个子类，这个机制就是尝试将 I 从Instruction类转换为CallInst类，如果转换成功，那么就会将转换后指向CallInst类的指针返回给auto *c

```
            if (auto *CalledF = c->getCalledFunction()) {
              if (!isBlacklisted(CalledF))
                bbcalls << bb_name << "," << CalledF->getName().str() << "\n";
            }
```

在转换成功的情况下（也就是这条指令确实是一条函数调用的指令），那么会获取这个调用指令要调用的那个函数的名称，并将这个调用关系存入BBcalls.txt这个文件中。

之后判断当前基本块是否有名称，如果有名字的话，则首先尝试使用setName给当前正在处理的这个BB（BasicBlock）对象进行命名

```
BB.setName(bb_name + ":");
```

如果失败了，那么就尝试使用更底层的方式来给其命名：

```
          if (!BB.hasName()) {
            std::string newname = bb_name + ":";
            Twine t(newname);
            SmallString<256> NameData;
            StringRef NameRef = t.toStringRef(NameData);
            MallocAllocator Allocator;
            BB.setValueName(ValueName::Create(NameRef, Allocator));
          }
```

这里的Twine 是LLVM提供的一种高效字符串处理和表示方式，SmallString是一种LLVM提供的轻型的字符串对象，StringRef 则是LLVM提供的一种轻型的字符串引用对象（只包含指向字符串的指针以及字符串的长度），MallocAllocator则是LLVM提供的内存分配接口，setValueName则可以看作是setName的一种更加底层的实现。

这个部分总的来说其实就是设置当前基本块的名称，并将这个名称保存进BBnames.txt文件中。

接下来如果当前处于aflgo的tracing模式的话，则向每个基本块的末尾进行一次插桩：

```c++
          auto *TI = BB.getTerminator();
          IRBuilder<> Builder(TI);

          Value *bbnameVal = Builder.CreateGlobalStringPtr(bb_name);
          Type *Args[] = {
              Type::getInt8PtrTy(M.getContext()) //uint8_t* bb_name
          };
          FunctionType *FTy = FunctionType::get(Type::getVoidTy(M.getContext()), Args, false);
          Constant *instrumented = M.getOrInsertFunction("llvm_profiling_call", FTy);
          Builder.CreateCall(instrumented, {bbnameVal});
```

getTerminator获取基本块的终止指令，创建一个IRBuilder对象，这是LLVM提供的通过编程方法对IR进行操作的一个便捷方法，它允许用户以编程的方法向ll文件中插入IR指令。

然后通过getInt8PtrTy返回一个代表i8（8位整数指针类型，在 C/C++ 中通常对应 `char*` 或 `uint8_t*`）的llvm::Type对象，并将其存储在一个Type *Args[] 的数组之中，这个数组是一个用于存储函数参数类型的数组（也就是后面要插入的函数所需要的参数的类型）

FunctionType则是用于创建或获取一个函数的类型，**`Type::getVoidTy(M.getContext())`**: 指定函数的**返回类型**为 `void`，**`false`**: 一个布尔值，表示该函数**不是一个可变参数函数**（即没有 `...`）。

M.getOrInsertFunction("llvm_profiling_call", FTy)则是获取一个函数的引用，如果不存在则插入其声明，这里其实就是获取需要插入的目标函数llvm_profiling_call的函数引用。

Builder.CreateCall(instrumented, {bbnameVal});则是实际的将这个调用llvm_profiling_call的指令插入到了基本块的末尾， {bbnameVal}是一个初始化列表，它作唯一参数传递给这个llvm_profiling_call函数，这里也对应了前面Type *Args[] 中的定义。

如果对于当前正在遍历的这个函数其中是存在由名称的基本块，则使用 LLVM 提供的 `WriteGraph` 函数，为每个函数输出 `.dot` 格式的控制流图。

如果这个基本块是目标基本块，则将这个基本块的名称输入到ftargets.txt之中，其他的基本块所在的函数则输入到fnames.txt这个文件之中。

### 距离插桩阶段

这即是由是否传入distance文件决定是否进入距离插桩的逻辑：

```c++
else {
    /* Distance instrumentation */

    LLVMContext &C = M.getContext();
    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#ifdef __x86_64__
    IntegerType *LargestType = Int64Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
#else
    IntegerType *LargestType = Int32Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
#endif
    ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
    ConstantInt *One = ConstantInt::get(LargestType, 1);

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
        0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

    for (auto &F : M) {

      int distance = -1;

      for (auto &BB : F) {

        distance = -1;

        if (is_aflgo) {

          std::string bb_name;
          for (auto &I : BB) {
            std::string filename;
            unsigned line;
            getDebugLoc(&I, filename, line);

            if (filename.empty() || line == 0)
              continue;
            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            bb_name = filename + ":" + std::to_string(line);
            break;
          }

          if (!bb_name.empty()) {

            if (find(basic_blocks.begin(), basic_blocks.end(), bb_name) == basic_blocks.end()) {

              if (is_selective)
                continue;

            } else {

              /* Find distance for BB */

              if (AFL_R(100) < dinst_ratio) {
                std::map<std::string,int>::iterator it;
                for (it = bb_to_dis.begin(); it != bb_to_dis.end(); ++it)
                  if (it->first.compare(bb_name) == 0)
                    distance = it->second;

              }
            }
          }
        }

        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));

        if (AFL_R(100) >= inst_ratio) continue;

        /* Make up cur_loc */

        unsigned int cur_loc = AFL_R(MAP_SIZE);

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        /* Load prev_loc */

        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

        /* Update bitmap */

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        /* Set prev_loc to cur_loc >> 1 */

        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        if (distance >= 0) {

          ConstantInt *Distance =
              ConstantInt::get(LargestType, (unsigned) distance);

          /* Add distance to shm[MAPSIZE] */

          Value *MapDistPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo());
          LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
          MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrDist = IRB.CreateAdd(MapDist, Distance);
          IRB.CreateStore(IncrDist, MapDistPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          /* Increase count at shm[MAPSIZE + (4 or 8)] */

          Value *MapCntPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
          LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
          MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
          IRB.CreateStore(IncrCnt, MapCntPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        }

        inst_blocks++;

      }
    }
  }
```

首先是定义了一部分LLVM IR中会使用到的数据类型，用于后续的指令构造

`Int8Ty`：1 字节，用于 bitmap；

`Int32Ty`：用于 cur_loc、prev_loc 等；

`Int64Ty`：在 x86_64 平台用于 distance 统计。

然后根据是否是64位平台定义了两个变量：LargestType、MapCntLoc，这两个变量的具体作用在后面再分析。

之后又有两个与前面相似的变量：MapDistLoc、One

AFLMapPtr与AFLPrevLoc则分别对应了传统插桩中afl_area_ptr以及__afl_prev_loc这两个全局变量，以afl_area_ptr为例：

```c++
    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
```

这里使用new 创建分配了一个GlobalVariable类的指针对象，设定这个全局变量的类型是Int8Ty（也就是uint8），非常量（其值可变，false的含义），并作为一个外部可见符号（GlobalValue::ExternalLinkage），初始值为0， 名字为__afl_area_ptr

*tips：这里创建初始化的这个内存空间在被编译的目标程序运行时可以在自己的进程空间内访问*

在完成需要用到的变量初始化之后，进入了一个对于每个函数以及其中基本块处理的嵌套循环：

首先是遍历模块中的每个函数，现将距离值distance初始化为-1，然后遍历该函数中的每个基本块。

进入对基本块的处理循环中，有一个对is_aflgo标志位的判断，但是我认为这里应该是一个冗余判断，进入这个处理的逻辑条件就是is_aflgo为true

对于每个基本块中的每条IR指令进行遍历，使用前面定义的getDebugLoc函数获取每条指令所处的文件以及在源文件中的行号，对于文件名为空或者行号为0的指令则跳过处理。对有文件名字的进行处理，去除文件名中的文件路径，并将其作为这个基本块的名字（bb_name）使用。

对于成功获取到bb_name的基本块，首先判断这个基本块名有没有存在于用户传入BBnames.txt文件中（也就是有没存在有在aflgo预处理阶段遍历到的基本块）

如果该基本块不在文件中且现在是选择插桩模式（is_selective），则跳出对于该基本块的处理：

```c++
            if (find(basic_blocks.begin(), basic_blocks.end(), bb_name) == basic_blocks.end()) {

              if (is_selective)
                continue;

            } 
```

如果在提供的文件中找到了这个对应的基本块，那么则对距离对象进行遍历获取该基本块到目标位置的距离：

```c++
                std::map<std::string,int>::iterator it;
                for (it = bb_to_dis.begin(); it != bb_to_dis.end(); ++it)
                  if (it->first.compare(bb_name) == 0)
                    distance = it->second;

              }
```

也就是通过将哈希表结构中每个键值对的键（对应基本块名称）取出与当前遍历到的基本块名称做对比，如果比对成功则将值赋给distance

*tips：这里的first是对应哈希表键值对中键，second是对应键值对中的值*

在准备好需要使用到的数据后，下面就进入了正式的插桩操作：

首先通过getFirstInsertionPt函数获取这个基本块的在phi指令后的第一个指令起始的位置（传统的插桩位置），选中 BB 的第一个插入点，使用 IRBuilder 来创建 IR 指令。

接下来的一部分的代码其实就是传统AFL的插桩逻辑：

```c++
		unsigned int cur_loc = AFL_R(MAP_SIZE);

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        /* Load prev_loc */

        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

        /* Update bitmap */

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        /* Set prev_loc to cur_loc >> 1 */

        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
```

这是对AFL中边覆盖率收集插桩的传统方法，如果了解AFL的插桩原理的话这部分就很容易理解

在MAP_SIZE的大小范围内取一个随机数作为当前基本块的ID，然后将其转化一个IR中32位的常量（cur_loc）。

之后获取上一个基本块的ID（PrevLoc），这个变量其实就是前面设置的__afl_prev_loc全局变量。同时创建一个元数据，将它命名为nosanitize，这步操作其实是在告诉sanitizer不要对此处的指令进行检测，因为插桩的代码本身就是注入的，这样是为了防止误报。最后对这个创建出来的PrevLoc对象进行0扩展，因为PrevLoc是用load指令加载的数据，它有可能是8位或者是16位的整数，为了方便后面的位运算，所以在这里要将其扩展至32位。

后面接着加载之前创建SHM虚拟共享内存的所在地址，这里的操作与之前获取PrevLoc的操作类似。

然后创建一个GEP指令，然后由异或指令PrevLoc与cur_loc进行异或，这个异或出来的值作为一条边的ID，同时作为bitmap中的索引，这就是AFL边覆盖率插桩的核心逻辑：

```c++
Value *MapPtrIdx = IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));
```

将前面获得的这个边的ID作为索引，在bitmap的对应位置上将其值+1

```c++
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
//CreateStore将自增后的值在bitmap的对应索引地址上进行更新
```

最后将AFLPrevLoc（prev_loc）的值设置为cur_loc >> 1后就结束传统AFL的插桩逻辑：

```c++
        /* Set prev_loc to cur_loc >> 1 */

        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
```

下面就是aflgo独有的距离插桩逻辑了：

```c++
if (distance >= 0) {

          ConstantInt *Distance =
              ConstantInt::get(LargestType, (unsigned) distance);

          /* Add distance to shm[MAPSIZE] */

          Value *MapDistPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo());
          LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
          MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrDist = IRB.CreateAdd(MapDist, Distance);
          IRB.CreateStore(IncrDist, MapDistPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          /* Increase count at shm[MAPSIZE + (4 or 8)] */

          Value *MapCntPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
          LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
          MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
          IRB.CreateStore(IncrCnt, MapCntPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        }
```

最开始判断distance是否存在，只对到目标位置有距离的基本块进行操作。

然后将前面获取到的distance转化为IR中的常量。
设置MapDistPtr，这是虚拟共享内存shm中位于MAP_SIZE的指针，也就是shm[MAP_SIZE]，从这个地址上取出当前的总距离值，也就是MapDist

将当前的总距离值加上该BB到目标位置的距离作为新的总距离值然后再将这个增加后的距离值写回shm[MAP_SIZE]

之后设置了一个MapCntPtr的变量，它的值来自于MapCntLoc，这个变量是紧挨着shm的一个aflgo的附加字段，根据前面的定义，其实就是shm[MAP_SIZE + 8]的位置。后面的操作就是将这个位置上的值+1后写回原地址

从意义上来说，这是一个对于距离累加次数的计数器。它用于模糊测试过程的对某条路径到达目标位置平均距离的计算，这个平均距离会影响对于种子的能量分配。

## 收尾处理

到这里这个aflgo-pass的内容差不多就结束了，剩下的部分就是一些pass所需要的特定操作以及一些运行信息的输出

```c++
  /* Say something nice. */

  if (!is_aflgo_preprocessing && !be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%, dist. ratio %u%%).",
             inst_blocks,
             getenv("AFL_HARDEN")
             ? "hardened"
             : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
               ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio, dinst_ratio);

  }
```

这里是像用户返回插桩过程的一些信息，比如插桩了多少个基本块，本次插桩的插桩率是多少等。

接下来的就是llvm pass中的对于一个pass的注册机制：

```c++
static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
```

这些操作是pass中的必要注册操作，首先将AFLCoverage添加到passmanager中，然后再通过RegisterAFLPass注册这个pass

这里可以看到注册了两次，但一个EP_OptimizerLast，一个是EP_EnabledOnOptLevel0，这是确保pass在不同的编译优化级别下都能运行。

# distance.py

这个程序用于处理前面由pass生成的dot文件，生成出对应的CG和CFG，并计算出后续需要用到的基本块到目标位置距离。

从这个函数的main函数入口来分析，首先它设置了一些脚本运行所需要的参数：

```python
  parser = argparse.ArgumentParser ()
  parser.add_argument ('-d', '--dot', type=str, required=True, help="Path to dot-file representing the graph.")
  parser.add_argument ('-t', '--targets', type=str, required=True, help="Path to file specifying Target nodes.")
  parser.add_argument ('-o', '--out', type=str, required=True, help="Path to output file containing distance for each node.")
  parser.add_argument ('-n', '--names', type=str, required=True, help="Path to file containing name for each node.")
  parser.add_argument ('-c', '--cg_distance', type=str, help="Path to file containing call graph distance.")
  parser.add_argument ('-s', '--cg_callsites', type=str, help="Path to file containing mapping between basic blocks and called functions.")

  args = parser.parse_args ()
```

这几个参数的含义分别是：

- 传入的dot文件的路径
- 传入包含目标位置的文件的路径
- 一个用于保存生成的每个节点（基本块）距离的路径
- 保存所有节点名称文件路径
- 保存CG中的距离文件的路劲
- 保存基本块与调用函数间（若基本块中存在函数调用）对应关系的文件路径

然后通过对传入的dot文件用networkx转化为图对象后，判断这个图中是否有“Call graph”字符串来决定是进入CG模式还是CFG模式。

```python
  print ("\nParsing %s .." % args.dot)
  G = nx.DiGraph(nx.drawing.nx_pydot.read_dot(args.dot))
  print (G)

  is_cg = "Call graph" in str(G)
  print ("\nWorking in %s mode.." % ("CG" if is_cg else "CFG"))
```

**整个距离计算的逻辑大概是：首先是CG模式获得所有对目标函数（或者说基本块）具有可达性的函数以及其到目标位置的距离，然后对于每个函数的生成的CFG进行基本块节点的遍历，如果这个这个基本块中存在对前面找到的对目标位置具有可达性的函数调用，那么就可以认为这个基本块对目标位置是存在可达关系的，那么就会对这个基本块做一个距离计算并将这个基本块和这个计算出的距离进行记录**

## CG中的距离计算

如果是CG模式的话，首先读取通过-t参数传入的目标文件中的目标位值信息，将其然后将可以在图中通过标签找到的那些目标加入到一个列表中（前面分析过CG图中的节点标签就是函数名）

```python
    print ("Loading targets..")
    with open(args.targets, "r") as f:
      targets = []
      for line in f.readlines ():
        line = line.strip ()
        for target in find_nodes(line):
          targets.append (target)
```

如果在目标文件中没有目标实际存在于CG中，则直接返回：

```python
    if (not targets and is_cg):
      print ("No targets available")
      exit(0)
```

然后通过distance函数实际计算每个节点到目标位置的距离：

```python
  print ("Calculating distance..")
  with open(args.out, "w") as out, open(args.names, "r") as f:
    for line in f.readlines():
      distance (line.strip())
```

## CFG中的距离计算

首先定义了几个需要用到的变量：

```
  caller = ""
  cg_distance = {}
  bb_distance = {}
```

然后检查参数是否正确传入：

```python

    if args.cg_distance is None:
      print ("Specify file containing CG-level distance (-c).")
      exit(1)

    elif args.cg_callsites is None:
      print ("Specify file containing mapping between basic blocks and called functions (-s).")
      exit(1)
```

如果在CFG模式下，有cg_distance cg_callsites参数没有传入的话则退出程序

然后将传入的中cg_distance的函数名与其距离值映射为一个键值对：

```python
      with open(args.cg_distance, 'r') as f:
        for l in f.readlines():
          s = l.strip().split(",")
          cg_distance[s[0]] = float(s[1])
```

对于函数间的调用，通过传入的cg_callsites中记录的调用关系，与前面记录的cg_distance中的函数间距离结合，构成基本块->调用函数的距离关系：

首先检查遍历到的这个基本块存不存在于CFG之中，如果存在，则判断由这个基本块调用的函数存不存在于之前记录的cg_distance中（也就是它调用的函数与目标位置是否可达）。

最后判断这个基本块的调用关系是不是调用了多个函数，如果是则保留调用的最小的那个距离值。

```python
      with open(args.cg_callsites, 'r') as f:
        for l in f.readlines():
          s = l.strip().split(",")
          if find_nodes(s[0]):
            if s[1] in cg_distance:
              if s[0] in bb_distance:
                if bb_distance[s[0]] > cg_distance[s[1]]:
                  bb_distance[s[0]] = cg_distance[s[1]]
              else:
                bb_distance[s[0]] = cg_distance[s[1]]
```

判断传入的目标文件中的目标基本块是不是存在于CFG之中，如果存在，则在bb_distance中将目标基本块本身的距离设置为0：

```python
      print ("Adding target BBs (if any)..")
      with open(args.targets, "r") as f:
        for l in f.readlines ():
          s = l.strip().split("/");
          line = s[len(s) - 1]
          if find_nodes(line):
            bb_distance[line] = 0
            print ("Added target BB %s!" % line)
```

## distance函数

这个是具体进行距离计算的函数，也是aflgo中描述基本块及函数间距离的具体实现，但在distance.py中的调用其实只有一处：

```
distance (line.strip())
```

进入函数之后首先判断是不是CG模式且传入的name参数有没有存在于bb_distance（字典对象）的键当中。

如果是CFG模式，且传入处理的BBname已经在bb_distance中被记录过，则将bb_distance中对应的BBname的距离乘10作为该BB到目标BB的距离写入距离文件中。

```python
  if not is_cg and name in bb_distance.keys():
    out.write(name)
    out.write(",")
    out.write(str(10 * bb_distance[name]))
    out.write("\n")
    return
```

然后遍历当前图中与传入name匹配的节点，如果是CG模式，则尝试使用迪杰斯特拉算法找到当前节点到目标节点间的最小距离，距离转换为 `1 / (1 + dist)` 的形式，所有路径的值累加起来，最后求 **加权平均的倒数**，用作最终评估距离。

```python
  for n in find_nodes (name):
    d = 0.0
    i = 0

    if is_cg:
      for t in targets:
        try:
          shortest = nx.dijkstra_path_length (G, n, t)
          d += 1.0 / (1.0 + shortest)
          i += 1
        except nx.NetworkXNoPath:
          pass
```

如果是CFG模式，则遍历bb_distance中的键值对，对于存在于CFG中的节点，尝试使用迪杰斯特拉算法找到这个节点到目标节点间的最近距离，然后计算路径距离 `shortest`，同时加上 10 倍的函数距离（`bb_d`）作为“穿过调用路径”的惩罚项（也就是一个跨函数的距离的倍率提升）。

这个计算公式大概就是：

```
d += 1 / (1 + 10 * bb_d + shortest_path_len)
```

同时，如果在CFG中同一个可以到达目标位置的基本块（节点）多次出现，那么距离值就取所有这个节点到目标位置距离的平均值：

```python
      for t_name, bb_d in bb_distance.items():
        di = 0.0
        ii = 0
        for t in find_nodes(t_name):
          try:
            shortest = nx.dijkstra_path_length(G, n, t)
            di += 1.0 / (1.0 + 10 * bb_d + shortest)
            ii += 1
          except nx.NetworkXNoPath:
            pass
        if ii != 0:
          d += di / ii
          i += 1
```

对于一个CFG中，最后到达目标位置的距离只取所有这个CFG中所有基本块计算得到的距离的最小值：

```python
    if d != 0 and (distance == -1 or distance > i / d) :
      distance = i / d
```

在完成计算后，将名称与距离的对应关系写入距离文件中保存：

```python
  if distance != -1:
    out.write (name)
    out.write (",")
    out.write (str (distance))
    out.write ("\n")
```

