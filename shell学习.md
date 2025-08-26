# 基础语法

## echo

输出命令

-n；将两个echo命令的输出连在一起

-e：将单双引号内的特殊字符（如\n等）解释为换行

## ||与&&

都是将两个命令进行组合，||是当前一个命令执行失败后执行后一个命令，&&是前一个命令执行成功后执行下一个命令。

如果想要两个命令都执行，那么就是用;来组合

## type

这个命令用于查看其他命令的类型。

例如：

```
➜  type echo
echo is a shell builtin
➜  type ls
ls is an alias for ls --color=tty
```

也可以使用-a参数获取所有定义：

```
➜  type -a echo
echo is a shell builtin
echo is /usr/bin/echo
echo is /bin/echo
```

## 快捷键：

- `Ctrl + L`：清除屏幕并将当前行移到页面顶部。
- `Ctrl + C`：中止当前正在执行的命令。
- `Shift + PageUp`：向上滚动。
- `Shift + PageDown`：向下滚动。
- `Ctrl + U`：从光标位置删除到行首。
- `Ctrl + K`：从光标位置删除到行尾。
- `Ctrl + W`：删除光标位置前一个单词。
- `Ctrl + D`：关闭 Shell 会话。
- `↑`，`↓`：浏览已执行命令的历史记录。

# 模式扩展

## ~扩展

~代表当前用户的主目录

~user扩展为user用户的主目录

~+会扩展为当前目录，等同于pwd

## ？扩展

？表示文件路劲里面的单个任意字符。

比如，`Data???`匹配所有`Data`后面跟着三个字符的文件名。

特殊的，在echo命令中，它会输出扩展后的结果；如果不能扩展成文件名，`echo`就会原样输出`?.txt`。

## *扩展

*表示文件路径里面的任意数量的字符

ls的*字符不会匹配隐藏文件夹或文件，如果需要匹配隐藏文件，则需要使用：

```
echo .*
```

## 方括号扩展

表示在文件存在的情况下，匹配方括号中任意一个字符时输出（这种用法不是很重要）

重要的是类似于这种：表示匹配一个连续的范围。比如，`[a-c]`等同于`[abc]`，`[0-9]`匹配`[0123456789]`。

下面是一些常用简写的例子。

- `[a-z]`：所有小写字母。
- `[a-zA-Z]`：所有小写字母与大写字母。
- `[a-zA-Z0-9]`：所有小写字母、大写字母与数字。
- `[abc]*`：所有以`a`、`b`、`c`字符之一开头的文件名。
- `program.[co]`：文件`program.c`与文件`program.o`。
- `BACKUP.[0-9][0-9][0-9]`：所有以`BACKUP.`开头，后面是三个数字的文件名。

## 大括号扩展

即使将括号内的值进行分隔，比如：

```
➜  echo {1,2,3}
1 2 3
```

逗号前也可以没有值，表示空：

```
(base) # youngmith in ~/temp/shell-test [10:13:21]
➜  cp a.txt{,.bak}
(base) # youngmith in ~/temp/shell-test [10:13:37]
➜  ls
a.txt  a.txt.bak
```

大括号可以嵌套，且其解释的优先级高于其它扩展。

另外，大括号还有一个{start..end}的扩展

跟前面方括号中类似，这个也是将括号中的内容从start扩展至end

这里也可以像在python中一样指定步长：

```
➜  echo {0..8..2}
0 2 4 6 8
```

这个意思就是扩展0到8，步长为2

## 变量扩展

美元符号$开头的词元会被视为变量：

```
(base) # youngmith in ~/temp/shell-test [10:22:08]
➜  echo $SHELL
/usr/bin/zsh
(base) # youngmith in ~/temp/shell-test [10:27:39]
➜  echo $PWD
/home/youngmith/temp/shell-test
```

## 子命令扩展

$()可以扩展为一个命令的执行结果，该命令的所有输出都会作为返回值

```
➜  echo $(date)
Thu Aug 7 10:37:45 CST 2025
```

并且其可以嵌套：

```
➜  echo $(ls $(pwd))
a.txt a.txt.bak
```

注意$()与前一个命令之间有一个空格

## 字符类

[[:class:]]表示一个字符类，可以扩展为一类字符中的某一个。

- `[[:alnum:]]`：匹配任意英文字母与数字
- `[[:alpha:]]`：匹配任意英文字母
- `[[:blank:]]`：空格和 Tab 键。
- `[[:cntrl:]]`：ASCII 码 0-31 的不可打印字符。
- `[[:digit:]]`：匹配任意数字 0-9。
- `[[:graph:]]`：A-Z、a-z、0-9 和标点符号。
- `[[:lower:]]`：匹配任意小写字母 a-z。
- `[[:print:]]`：ASCII 码 32-127 的可打印字符。
- `[[:punct:]]`：标点符号（除了 A-Z、a-z、0-9 的可打印字符）。
- `[[:space:]]`：空格、Tab、LF（10）、VT（11）、FF（12）、CR（13）。
- `[[:upper:]]`：匹配任意大写字母 A-Z。
- `[[:xdigit:]]`：16进制字符（A-F、a-f、0-9）。

另外，第一个[]中可以引入！或^表示否定，比如：

```
echo [![:digit:]]*
```

表示所有不以数字开头的文件名

# 引号与转义

## 转义

正常来说，当输入：

```
echo $SHELL
```

的时候,$SHELL会被当做变量解释，如果就想输出$SHELL这个字符串呢？那就必须要进行转义了

在这种特殊字符的前面加上\，就可以完成转义：

```
root@3b638823b4ef:/src/gpac# echo \$SHELL
$SHELL
```

而\本身也是一个特殊字符，所以当要输出这个转移字符的时候，就也需要进行转义：

```
root@3b638823b4ef:/src/gpac# echo \\
\
```

与高级语言中类似，以\开头存在一些具有特殊意义的字符：

- `\a`：响铃
- `\b`：退格
- `\n`：换行
- `\r`：回车
- `\t`：制表符

但是如果直接加入这些字符使用echo的话，那么是无法正确解释输出的：

```
root@3b638823b4ef:/src/gpac# echo a\nb
anb
```

这里的\被识别为一个特殊字符，根据前面提到过的，echo命令需要-e参数来解释这些特殊字符

```
root@3b638823b4ef:/src/gpac# echo -e "a\nb"
a
b
```

另外，\可以进行多行命令的写法:

```
root@3b638823b4ef:/src/gpac# echo abc \
> cba
abc cba
```

## 双引号

双引号比单引号宽松，大部分的特殊字符在里面会失去原有的意义，变成普通字符，比如*

但是还是有三个字符在里面是正常被解释的：

美元符号（`$`）、反引号（`）和反斜杠（\）

有一种双引号常见的使用场景就是在当文件中包含空格的时候，如果不使用双引号的话就会被就是为是两个文件。

还有一个重要的用途就是保存原始命令的输出格式。

# 变量

## 创建变量

由用户创建变量的时候，变量名需要遵守以下规则：

- 字母、数字和下划线字符组成。
- 第一个字符必须是一个字母或一个下划线，不能是数字。
- 不允许出现空格和标点符号。

变量可以重复赋值，但是后面的赋值会覆盖掉前面的赋值

同一行中如果想要定义多个变量，则需要;进行分割

## 读取变量

在变量名前加上$即可读取变量名

读取变量名时也可以用{}将变量名包裹起来，这种用法一般出现在将变量名与其他字符串连用的时候：

```
$ echo ${a}_file
```

当变量本身的值本身也是变量的时候（类似于高级语言中的引用一样），我们可以使用一种叫做简介引用的方式来读取这个变量：

```
$ myvar=PWD
$ echo ${!myvar}
```

当直接使用：

```
echo ${myvar}
```

shell会回显：

```
PWD
```

但是，如果使用简介引用的话，shell则会回显;

```
root@59d53587488a:/test# echo ${!myvar}
/test
```

*tips:这个语法在zsh环境下使用(P)标志来完成*

另外，当变量中包含连续空格这种特殊情况（shell会把连续的空格合并为一个空格），最好在赋值的时候用" "把值包起来

## 删除变量

使用unset命令来删除一个变量

但是由于shell环境下的特性，不存在或者读取不到的变量统一都是空字符串，所以unset本质上就是把某个变量设置为空字符串。

## 输出变量

在前面提到的env命令只会在临时的、被修改过的环境中运行一个命令（也就是说env设置的变量只对带有它的这个命令生效一次）

而export命令则是让一个变量“导出”为一个环境变量，从而使这个shell中的其他命令（或者程序）、以及它的子shell也能继承这个变量。

## 特殊变量

bash中提供一些特殊的变量。这些变量的值由shell 提供，用户不能赋值

（1）`$?`

`$?`为上一个命令的退出码，用来判断上一个命令是否执行成功。返回值是`0`，表示上一个命令执行成功；如果不是零，表示上一个命令执行失败。

（2）`$$`

`$$`为当前 Shell 的进程 ID。

（3）`$_`

`$_`为上一个命令的最后一个参数。

（4）`$!`

`$!`为最近一个后台执行的异步命令的进程 ID。（可以理解为挂在后台执行的程序）

（5）`$0`

`$0`为当前 Shell 的名称（在命令行直接执行时）或者脚本名（在脚本中执行时）。

（6）`$-`

`$-`为当前 Shell 的启动参数。

## 变量的默认值

Bash 提供四个特殊语法，跟变量的默认值有关，目的是保证变量不为空。

```
${varname:-word}
```

上面语法的含义是，如果变量`varname`存在且不为空，则返回它的值，否则返回`word`。它的目的是返回一个默认值，比如`${count:-0}`表示变量`count`不存在时返回`0`。但是varname的值还是空

```
${varname:=word}
```

上面语法的含义是，如果变量`varname`存在且不为空，则返回它的值，否则将它设为`word`，并且返回`word`。它的目的是设置变量的默认值，比如`${count:=0}`表示变量`count`不存在时返回`0`，且将`count`设为`0`。此时varname的值是word

```
${varname:+word}
```

上面语法的含义是，如果变量名存在且不为空，则返回`word`，否则返回空值。它的目的是测试变量是否存在，比如`${count:+1}`表示变量`count`存在时返回`1`（表示`true`），否则返回空值。

```
${varname:?message}
```

上面语法的含义是，如果变量`varname`存在且不为空，则返回它的值，否则打印出`varname: message`，并中断脚本的执行。如果省略了`message`，则输出默认的信息“parameter null or not set.”。它的目的是防止变量未定义，比如`${count:?"undefined!"}`表示变量`count`未定义时就中断执行，抛出错误，返回给定的报错信息`undefined!`。

上面四种语法如果用在脚本中，变量名的部分可以用数字`1`到`9`，表示脚本的参数。

```
filename=${1:?"filename missing."}
```

上面代码出现在脚本中，`1`表示脚本的第一个参数。如果该参数不存在，就退出脚本并报错。

## declare命令

这个命令与export有一些相似之处，但是declare命令可以显式的指定变量的类型。

另外，declare在直接输入不带任何参数的情况下等同于set命令，都会回显所有的变量及其值；且如果在一个函数体内使用declare声明变量，那么这个变量的作用域只在这个函数当中，等同于local命令

declare命令的主要参数为：

- `-a`：声明数组变量。
- `-f`：输出所有函数定义。
- `-F`：输出所有函数名。
- `-i`：声明整数变量。
- `-l`：声明变量为小写字母。
- `-p`：查看变量信息。
- `-r`：声明只读变量。
- `-u`：声明变量为大写字母。
- `-x`：该变量输出为环境变量。

**（1）`-i`参数**

`-i`参数声明整数变量以后，可以直接进行数学运算。

```
$ declare -i val1=12 val2=5
$ declare -i result
$ result=val1*val2
$ echo $result
60
```

上面例子中，如果变量`result`不声明为整数，`val1*val2`会被当作字面量，不会进行整数运算。另外，`val1`和`val2`其实不需要声明为整数，因为只要`result`声明为整数，它的赋值就会自动解释为整数运算。

注意，一个变量声明为整数以后，依然可以被改写为字符串。

```
$ declare -i var=12
$ var=foo
$ echo $var
0
```

**（2）`-x`参数**

`-x`参数等同于`export`命令，可以输出一个变量为子 Shell 的环境变量。

```
$ declare -x foo
# 等同于
$ export foo
```

**（3）`-r`参数**

-r选项声明只读变量，无法改变变量值，也不能`unset`变量。

**（4）`-u`参数**

`-u`参数声明变量为大写字母，可以自动把变量值转成大写字母。

**（5）`-l`参数**

`-l`参数声明变量为小写字母，可以自动把变量值转成小写字母。

**（6）`-p`参数**

`-p`参数输出变量信息。

在-p后接某个变量的名称可以输出这个变量的相关信息：

```
root@59d53587488a:/test# declare -p bar
declare -r bar
```

如果直接输入-p不接任何变量名的话则输出所有的变量相关信息

**（7）`-f`参数**

`-f`参数输出当前环境的所有函数，包括它的定义。

**（8）`-F`参数**

`-F`参数输出当前环境的所有函数名，不包含函数定义。

## readonly命令

这个命令的作用域declare -r 的作用是一样的，用于声明一个只可读的变量，这个变量在被声明之后不能修改其值，也不能被unset掉。

`readonly`命令有三个参数。

- `-f`：声明的变量为函数名。
- `-p`：打印出所有的只读变量。
- `-a`：声明的变量为数组。

## let命令

这个命令也是用于声明变量，通过这个命令声明的变量可以在声明的时候执行算数表达式来给变量赋值。

```
root@59d53587488a:/test# let foo=1+2
root@59d53587488a:/test# echo $foo
3
```

当let命令声明的变量表达式中包含空格时，需要将其用“ ”包起来。

```
root@59d53587488a:/test# let "foo = 2 + 2"
root@59d53587488a:/test# echo $foo
4
```

let命令也可以声明多个变量，变量用空格隔开

```
root@59d53587488a:/test# let "var1 = 3 + 3" "var2 = 4 + 4"
root@59d53587488a:/test# echo $var1; echo $var2
6
8
```

# 字符串操作

## 字符串的长度

获取字符串长度的语法为;

```
${#varname}
```

例如：

```
(base) # youngmith in ~/temp/shell-test [10:49:35] C:1
➜  mystring=youngmith
(base) # youngmith in ~/temp/shell-test [10:56:34]
➜  echo ${#mystring}
9
```

**大括号是必须的**，否则$#会被理解为

## 子字符串

提取子字符串的语法为：

```
${varname:offset:length}
```

这个语法会返回$varname字符串从offset处开始（从0开始计数），长度为length的子字符串

例如：

```
➜  echo ${mystring:0:5}
young
```

tips：这个语法是不能直接操作字符串的，也就是varname必须要是一个变量。

如果语法中省略掉length参数，那么就会返回从offset开始到结尾的字符串

另外，如果offset为负数，那么就会从字符串末尾开始计算，但是length仍然是往前走

例如：

```
➜  echo ${mystring: -4:4}
mith
```

**tips：注意在使用这个语法时，为负数的offset要与:前有一个空格，这是为了防止这个负数语法被识别为前面对于变量默认值的操作**

## 搜索与替换

**（1）字符串头部的模式匹配。**

以下的两种语法会检查字符串的开头。如果匹配成功，则删除匹配到的部分，输出剩下的部分，但是不会影响原本变量中的字符串

```
# 如果 pattern 匹配变量 variable 的开头，
# 删除最短匹配（非贪婪匹配）的部分，返回剩余部分
${variable#pattern}

# 如果 pattern 匹配变量 variable 的开头，
# 删除最长匹配（贪婪匹配）的部分，返回剩余部分
${variable##pattern}
```

例如：

```
➜  mystring=youngmithyoungmith666
(base) # youngmith in ~/temp/shell-test [11:35:40]
➜  echo ${mystring#youngmith}
youngmith666
```

也可以使用* 、?、[]等通配符

例如：

```
➜  myPath=/home/cam/book/long.file.name
(base) # youngmith in ~/temp/shell-test [11:39:44]
➜  echo ${myPath#/*/}
cam/book/long.file.name
(base) # youngmith in ~/temp/shell-test [11:39:57]
➜  echo ${myPath##/*/}
long.file.name
```

当匹配不成功时，会返回原字符串

如果要将头部匹配的部分换成其他的字符串，则需要使用到下面这个语法：

```
${varname/pattern/string}
```

例如：

```
➜  echo $mystring
youngmithyoungmith666
(base) # youngmith in ~/temp/shell-test [11:43:16]
➜  echo ${mystring/young/old}
oldmithyoungmith666
```

**（2）字符串尾部的模式匹配**

与头部匹配相似，也存在尾部匹配，其遵循以下两种语法，输出时会删除匹配成功的部分，但原始的字符串变量中的字符串不受影响。

```
# 如果 pattern 匹配变量 variable 的结尾，
# 删除最短匹配（非贪婪匹配）的部分，返回剩余部分
${variable%pattern}

# 如果 pattern 匹配变量 variable 的结尾，
# 删除最长匹配（贪婪匹配）的部分，返回剩余部分
${variable%%pattern}
```

例如：

```
➜  echo ${mystring%666}
youngmithyoungmith
```

另外，在头部匹配中的那些特性在这里面也一样可以使用

**（3）任意位置的模式匹配。**

以下的两种语法可以匹配目标字符串中的子串。无论子串的位置是在什么地方；与之前相同，输出会删除掉匹配到的子串，但是原本变量中的字符串不会受到影响。

```
# 如果 pattern 匹配变量 variable 的一部分，
# 最长匹配（贪婪匹配）的那部分被 string 替换，但仅替换第一个匹配
${variable/pattern/string}

# 如果 pattern 匹配变量 variable 的一部分，
# 最长匹配（贪婪匹配）的那部分被 string 替换，所有匹配都替换
${variable//pattern/string}
```

这两个语法中的string参数都是可选的，如果没有这个参数的话，就只完成“匹配  删除”的操作。如果填入了这个参数  那么就会完成“匹配  替换”的操作

```
➜  echo ${mystring/oung}
ymithyoungmith666
(base) # youngmith in ~/temp/shell-test [15:07:26]
➜  echo ${mystring//oung}
ymithymith666


(base) # youngmith in ~/temp/shell-test [15:07:33]
➜  echo ${mystring/young/old}
oldmithyoungmith666
(base) # youngmith in ~/temp/shell-test [15:10:15]
➜  echo ${mystring//young/old}
oldmitholdmith666
```

另外，这个语法还有两种变异的头部和尾部匹配的扩展：

```
# 模式必须出现在字符串的开头
${variable/#pattern/string}

# 模式必须出现在字符串的结尾
${variable/%pattern/string}
```

这种写法实质上就是完成了子串替换的头部和尾部匹配，例如：

```
(base) # youngmith in ~/temp/shell-test [15:14:54]
➜  echo ${mystring/%young/old}
youngmithyoungmith666
(base) # youngmith in ~/temp/shell-test [15:14:59]
➜  echo ${mystring/%666/old}
youngmithyoungmithold
```

## 改变大小写

下面的这个语法可以改变变量的大小写：

```
# 转为大写
${varname^^}

# 转为小写
${varname,,}
```

例如：

```
root@59d53587488a:/test# mystring=youngmith
root@59d53587488a:/test# echo ${mystring,,}
youngmith
root@59d53587488a:/test# echo ${mystring^^}
YOUNGMITH
```

# 算术运算

## 算术表达式

下面这个语法可以进行整数的算术运算：

```
((...))
```

例如：

```
➜  echo $((1+2))
3
```

且((...))语法会忽略掉括号内的空格，所以在括号内打不打空格都是一样的。

直接在shell中输入这个命令是不返回值的，只要它的计算结果不为0，那么它的结束状态就是正常结束：

```
root@59d53587488a:/test# ((1+1))
root@59d53587488a:/test# echo $?
0
```

相同的，如果计算结果为0，那么就算是执行失败：

```
root@59d53587488a:/test# ((1-1))
root@59d53587488a:/test# echo $?
1
```

`((...))`语法支持的算术运算符如下。

- `+`：加法
- `-`：减法
- `*`：乘法
- `/`：除法（整除）
- `%`：余数
- `**`：指数
- `++`：自增运算（前缀或后缀）
- `--`：自减运算（前缀或后缀）

另外需要注意的是，这个命令只返回整数，如果运算结果有小数会直接去掉小数部分。

`++`和`--`这两个运算符有前缀和后缀的区别。作为前缀是先运算后返回值，作为后缀是先返回值后运算。

```
root@59d53587488a:/test# i=0
root@59d53587488a:/test# echo $((i++))
0
root@59d53587488a:/test# echo $((++i))
2
```

`$((...))`内部可以用圆括号改变运算顺序：

```
root@59d53587488a:/test# echo $(((4-2)*5))
10
```

这个语法中返回的值可以有小数（虽然会被忽略），但是参与计算的值必须为整数，使用小数会报错：

```
root@59d53587488a:/test# echo $((1.5+1))
bash: 1.5+1: syntax error: invalid arithmetic operator (error token is ".5+1")
```

`$((...))`的圆括号之中，不需要在变量名之前加上`$`，不过加上也不报错。

如果在`$((...))`里面使用字符串，Bash 会认为那是一个变量名。如果不存在同名变量，Bash 就会将其作为空值，因此不会报错

```
root@59d53587488a:/test# echo $(("hello"+2))
2
```

利用上面这个特性，可以完成一些动态替换的操作：

```
root@59d53587488a:/test# foo=hello
root@59d53587488a:/test# hello=3
root@59d53587488a:/test# echo $((foo + 2))
5
```

可以看到foo的值由hello决定，而$((  ))最后会将foo解析为hello

## 数值的进制

Bash中的数值默认为十进制，但是在算术表达式中，可以使用其他进制

- `number`：没有任何特殊表示法的数字是十进制数（以10为底）。
- `0number`：八进制数。（012345）
- `0xnumber`：十六进制数。(0xff)
- `base#number`：`base`进制的数。(2#1111111)

例如：

```
root@59d53587488a:/test# echo $((012345))
5349
root@59d53587488a:/test# echo $((0xff))
255
root@59d53587488a:/test# echo $((2#111111))
63
```

## 位运算

`$((...))`支持以下的二进制位运算符。

- `<<`：位左移运算，把一个数字的所有位向左移动指定的位。
- `>>`：位右移运算，把一个数字的所有位向右移动指定的位。
- `&`：位的“与”运算，对两个数字的所有位执行一个`AND`操作。
- `|`：位的“或”运算，对两个数字的所有位执行一个`OR`操作。
- `~`：位的“否”运算，对一个数字的所有位取反。
- `^`：位的异或运算（exclusive or），对两个数字的所有位执行一个异或操作。

下面是左右移的例子：

```
root@59d53587488a:/test# echo $((16>>2))
4
root@59d53587488a:/test# echo $((16<<2))
64
```

下面是其他几种位运算的实例：

```
root@59d53587488a:/test# echo $((17 & 3))
1
root@59d53587488a:/test# echo $((17 | 3))
19
root@59d53587488a:/test# echo $((~17))
-18
root@59d53587488a:/test# echo $((17^3))
18
```

## 逻辑运算

`$((...))`支持以下的逻辑运算符。

- `<`：小于
- `>`：大于
- `<=`：小于或相等
- `>=`：大于或相等
- `==`：相等
- `!=`：不相等
- `&&`：逻辑与
- `||`：逻辑或
- `!`：逻辑否
- `expr1?expr2:expr3`：三元条件运算符。若表达式`expr1`的计算结果为非零值（算术真），则执行表达式`expr2`，否则执行表达式`expr3`。

如果逻辑表达式的结果为真，那么则会返回1，否则就会返回0

```
root@59d53587488a:/test# echo $((2 > 1))
1
root@59d53587488a:/test# echo $(( (3 > 1) || (4 < 1) ))
1
root@59d53587488a:/test# echo $(( (3 > 1) && (4 < 1) ))
0
```

对于三元运算符：

```
root@59d53587488a:/test# a=1
root@59d53587488a:/test# echo $((a!=1?0:1))
1
```

翻译一下这个操作就是a是不是真的不等于1，如果是的话则返回0不是的话则返回1

## 赋值运算

算术表达式`$((...))`可以执行赋值运算。

```
root@59d53587488a:/test# echo $((a=3))
3
root@59d53587488a:/test# echo $a
3
```

对于这个赋值表达式，它是有返回值的，也就是给a赋的值3

`$((...))`支持的赋值运算符，有以下这些。

- `parameter = value`：简单赋值。
- `parameter += value`：等价于`parameter = parameter + value`。
- `parameter -= value`：等价于`parameter = parameter – value`。
- `parameter *= value`：等价于`parameter = parameter * value`。
- `parameter /= value`：等价于`parameter = parameter / value`。
- `parameter %= value`：等价于`parameter = parameter % value`。
- `parameter <<= value`：等价于`parameter = parameter << value`。
- `parameter >>= value`：等价于`parameter = parameter >> value`。
- `parameter &= value`：等价于`parameter = parameter & value`。
- `parameter |= value`：等价于`parameter = parameter | value`。
- `parameter ^= value`：等价于`parameter = parameter ^ value`。

例如：

```
root@59d53587488a:/test# b=10
root@59d53587488a:/test# echo $((b+=2))
12
root@59d53587488a:/test# echo $b
12
```

## 求值运算

逗号`,`在`$((...))`内部是求值运算符，执行前后两个表达式，并返回后一个表达式的值。

例如：

```
root@59d53587488a:/test# echo $((foo=5, 1+2))
3
root@59d53587488a:/test# echo $foo
5
```

## expr命令

expr命令与$((  ))语法类似，都是进行算术运算，但是当前推荐使用$(())，这个语法更现代也更方便

## let命令

`let`命令用于将算术运算的结果，赋予一个变量

前面有讲过，不多赘述

# 操作历史

bash会保存用户的操作历史

当用户退出shell的时候，bash会默认把用户的操作历史保存在`~/.bash_history`文件，该文件默认储存500个操作。

而环境变量HISTFILE就默认指向这个文件：

```
➜  echo $HISTFILE
/home/youngmith/.zsh_history
```

## history命令

history命令会输出所有的操作历史，也就是输出HHISTFILE文件的内容：

相比直接读取`.bash_history`文件，它的优势在于所有命令之前加上了行号。最近的操作在最后面，行号最大。

如果想搜索某个以前执行过的命令，则可以配合使用grep和less这种文本阅读相关的命令

另外，下面这个命令：

```
history -c
```

可以直接清空所有的操作历史，也就是直接清空HISTFILE文件

##  环境变量

### HISTTIMEFORMAT

通过定制这个环境变量：HISTTIMEFORMAT，可以让命令history的返回按照一定的时间格式显示：

```
$ export HISTTIMEFORMAT='%F %T  '
$ history
1  2013-06-09 10:40:12   cat /etc/issue
2  2013-06-09 10:40:12   clear
```

上面代码中，`%F`相当于`%Y - %m - %d`（年-月-日），`%T`相当于`%H : %M : %S`（时:分:秒）。

而在zsh中，定制操作历史的时间戳方法则不相同：

```
(base) # youngmith in ~ [16:17:27]
➜  setopt EXTENDED_HISTORY
(base) # youngmith in ~ [16:17:37]
➜  alias history='fc -l -i %F %T'
(base) # youngmith in ~ [16:18:22]
➜  fc -l -i
 3225  2025-08-25 20:23  cd auto_harness
 3226  2025-08-25 20:23  ls
 3227  2025-08-26 16:02  /usr/bin/python3 /home/youngmith/.vscode-server/extensions/ms-python.python-2025.12.0-linux-x64/python_files/printEnvVariablesToFile.py /home/youngmith/.vscode-server/extensions/ms-python.python-2025.12.0-linux-x64/python_files/deactivate/zsh/envVars.txt
 3228  2025-08-26 16:02  docker
 3229  2025-08-26 16:04  echo $HISTFILE
 3230  2025-08-26 16:06  history | less
 3231  2025-08-26 16:12  export HISTTIMEFORMAT='%F %T  '
 3232  2025-08-26 16:13  history | less
 3233  2025-08-26 16:13  history
 3234  2025-08-26 16:13  echo $HISTTIMEFORMAT
 3235  2025-08-26 16:15  unset HISTTIMEFORMAT
 3236  2025-08-26 16:15  echo $HISTTIMEFORMAT
 3237  2025-08-26 16:17  celar
 3238  2025-08-26 16:17  clear
 3239  2025-08-26 16:17  setopt EXTENDED_HISTORY
 3240  2025-08-26 16:18  alias history='fc -l -i %F %T'
```

首先要通过 setopt EXTENDED_HISTORY开启时间戳记录，然后使用alias给fc命令挂一个别名为history（其实本质上history就是fc命令的一个别名）

### HISTSIZE

这个环境变量用于设置历史保存的最大数量：

```
$ export HISTSIZE=10000
```

上面这个命令就是设置操作历史的最大保留为10000

那么，如果讲HISTSIZE设置为0，则是不需要保存此次操作的历史

另外，如果在bashrc文件中将这个环境变量设置为0，则是不保存该用户的操作历史。如果写入`/etc/profile`，整个系统都不会保留操作历史。

## ctrl r

输入命令时按下ctrl r，就等于对`.bash_history`文件进行搜索，直接键入命令的开头部分，shell就会自动在该文件中反向查询（即查找最近的命令），然后按下回车即可执行这个命令

## ！命令

### !+行号

操作历史的每一条记录都是有行号的。知道命令的行号可以直接使用`感叹号 + 行号`执行该命令：

```
$ !8
```

这就是执行`.bash_history`里面的第8条命令

### !-数字

如果想执行本次 Shell 对话中倒数的命令，比如执行倒数第3条命令，就可以输入`!-3`。

### !!

`!!`命令返回上一条命令。

```
(base) # youngmith in ~ [16:44:50]
➜  !!
(base) # youngmith in ~ [16:44:52]
➜  ls
```

### !+搜索词

`感叹号 + 搜索词`可以快速执行匹配的命令。

注意，`感叹号 + 搜索词`语法只会匹配命令，不会匹配参数。

```
(base) # youngmith in ~ [16:45:20]
➜  !c
(base) # youngmith in ~ [16:46:38]
➜  clear
```

由于!加搜索词会进行搜索，所以在有些字符串中使用！的话需要加上转义字符：

```
$ echo "I say:\"hello\!\""
```

上面这个命令中，如果去掉!前的那个\的话就会造成错误，bash会把!识别成一个查找字符

### !? + 搜索词

`!? + 搜索词`可以搜索命令的任意部分，包括参数部分。它跟`! + 搜索词`的主要区别是，后者是从行首开始匹配。

另外，这个操作就可以匹配命令用到的参数部分了

```
➜  echo helloworld
helloworld
(base) # youngmith in ~ [16:50:09]
➜  !?hello
(base) # youngmith in ~ [16:50:15]
➜  echo helloworld
```

### !$，!*

`!$`代表上一个命令的最后一个参数，它的另一种写法是`$_`。

`!*`代表上一个命令的所有参数，即除了命令以外的所有部分。

```
$ cp a.txt b.txt
$ echo !$
b.txt

$ cp a.txt b.txt
$ echo !*
a.txt b.txt
```

如果想匹配上一个命令的某个指定位置的参数，使用`!:n`。比如!:2就是返回上一条命令的第二个参数

如果想寻找比较久之前的某条命令的某个参数，可以使用下面这个语法：

```
!<命令>:n（指定位置的参数）和!<命令>:$（最后一个参数）。
```

### !:p

如果只是想输出上一条命令，而不执行他，那么就使用：!:p

```
(base) # youngmith in ~ [17:16:32]
➜  !:p
(base) # youngmith in ~ [17:16:53]
➜  cd ~
```

在zsh中，!! !:p 之间没有什么区别

如果想输出最近一条匹配的命令，而不执行它，可以使用`!<命令>:p`

```
(base) # youngmith in ~ [17:16:53]
➜  !su:p
(base) # youngmith in ~ [17:18:37]
➜  sudo chown -R youngmith:youngmith initramfs
```

这个例子中就是找到最近的su命令

在开启histverify参数的情况下， !+搜索词和这个!:p的作用是一样的

## histverify 参数

上面的那些快捷命令（比如`!!`命令），都是找到匹配的命令后，直接执行。如果希望增加一个确认步骤，先输出是什么命令，让用户确认后再执行，可以打开 Shell 的`histverify`选项。

打开`histverify`这个选项后，使用`!`快捷键所返回的命令，就会先输出，等到用户按下回车键后再执行。

在zsh中，使用：

```
setopt | grep hist
```

来确定是否开启了这个选项
