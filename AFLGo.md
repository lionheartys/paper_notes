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

这里用example中的目标项目尝试生成一下中间的BBname和BBcalls文件来看一下它们的具体内容是什么。



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

**persistent模式（持续化模式）：**

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

**deferred模式（forkserver 延迟启动）：**

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