# 基础语法

## echo

输出命令

-n；将两个echo命令的输出连在一起

-e：将单双引号内的特殊字符（如\n等解释为换行）

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