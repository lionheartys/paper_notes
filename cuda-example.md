# cuda-example

## 调用图与顺序图

项目中使用NVIDIA提供的操作手册和一些实例程序抽取了调用图（call graph）和顺序图（order graph）。是完全依赖大模型结合提示词工程进行抽取，格式存储为一个json文件。从操作手册中抽取了call graph，从示例程序中抽取了order graph。其通过大模型抽取的api调用链在json文件中的呈现为：

call graph：

```
[{"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaSetDevice", "tail_type": "CUDA_API"}, 
{"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaStreamCreateWithFlags", "tail_type": "CUDA_API"}, 
{"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaMallocAsync", "tail_type": "CUDA_API"}, 
{"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaMemcpyAsync", "tail_type": "CUDA_API"},
 {"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaFreeAsync", "tail_type": "CUDA_API"}, 
{"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaStreamSynchronize", "tail_type": "CUDA_API"}, 
{"head": "vectorAddGPU", "head_type": "__global__", "description": "Adds two vectors on the GPU.", "relation": "calls", "tail": "cudaMemcpyAsync", "tail_type": "CUDA_API"}, 
{"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaDeviceGetDefaultMemPool", "tail_type": "CUDA_API"}, 
{"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaMemPoolSetAttribute", "tail_type": "CUDA_API"}, 
{"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaEventRecord", "tail_type": "CUDA_API"}, 
{"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaEventSynchronize", "tail_type": "CUDA_API"}, 
{"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaEventElapsedTime", "tail_type": "CUDA_API"}, 
{"head": "checkCudaErrors", "head_type": "__host__", "description": "Checks for CUDA errors.", "relation": "calls", "tail": "cudaEventCreate", "tail_type": "CUDA_API"}]}
```

这些head description relation tail之类的是用提示词工程抽出来的对于调用关系的描述

order graph：

```
 {"order": [["cudaOccupancyMaxPotentialClusterSize", "cudaOccupancyMaxPotentialClusterSize"], ["__cluster_dims__", "cudaLaunchKernelEx"], ["cudaLaunchKernelEx", "cudaLaunchAttributeClusterDimension"], ["num_threads", "num_blocks"], ["dim_threads", "dim_blocks"]]}}
```

这里的order graph是调用顺序关系，是通过示例程序抽取了其中各个api 之间的调用关系

## 构建关系图谱

前面抽出来的调用图和顺序图被用于后面构建这个关系图谱

通过检索cuda中的.a文件确定所有的api签名，存储为一个包含所有唯一api的集合，用于过滤前面LLM抽取来的api序列

然后就是建图，这里使用了一个python库：**networkX**，这个可以用于构建各种各样的网络

总的来说就是结合前面的提取出来的json文件中的信息来生成一个关系图谱，因为json里面存储的信息都是api的链式关系，所以不需要进行过多的处理就能直接搓出来一张关系图（有向图），图的边被分为两类：call和order，根据其是在什么json里面被构建的

随机取出图中的一个节点，判断该节点是否入度大于1，如果是的话，通过广度优先搜索找到以其为源节点的五条路径

## 维护bitmap

统计了前面构建的关系图谱中call边和order边数量，进行了一定处理，删除了图中的一些明显错误的节点和边（比如自己调用自己的边就会被删掉）

然后为每一个API生成一个独特的ID，对于两个节点中间的边结合两个节点在前面被分配的独特ID构造了这个边的独特ID

到这里完成对于前面通过示例程序和操作手册提取的调用关系和顺序关系在bitmap里面的映射

然后后面如果通过fuzz触发了新的API则会把这个API设置ID后添加进bitmap之中

## 生成harness

首先初始化关系图谱，并通过初始关系图谱初始化bitmap。

首先抽出原始关系图谱中的5条路径（路径采样），对于采样到的5条路径（这里的节点为随机选择，可能并不是一个传统意义上的源节点）中的每一条，抽取出这条路径中的调用关系如下：

```
        Return's format is:
          1:  [ api1 calls api2, ..., apin calls apin+1 ]
          2:  [ (api1, api2), ..., (apin, apin+1) ]
```

在这里对于采样到的每一条路径遍历其中的节点间的路径并结合初始api order bitmap看是否找到了新的order（同理也判断了下是不是找到了新的call）

最后会记录两个bitmap，分别是bitmap_api_order_edge_trace和bitmap_api_call_edge_trace

之后就进入了harness的生成过程，首先是使用路径抽样出来的5条路径来生成harness，这里的提示词限制了大模型必须按给出的API顺序构建harness

 提示词要求大模型给出了生成的harness以及这个harness对应的编译命令

然后根据大模型给出的编译命令进行尝试编译，进行若干轮bugfix，主要原理是通过报错信息来修复一些可以人力修复的bug，比如去除一些可能是有LLM编造的API名字。

然后将根据前面的报错API结合一段prompt发给LLM让其尝试修复后得到修复代码

之后又对这个生成的harness进行了一次重构和再一次的测试编译 （即为代码中的_sep，但是暂时没搞懂这一步的含义是什么？->这一步是为了分离出原始harness中可以被抽取出来做变异的harness，利用大模型抽取可以被独立变异的变量）

后续的wrap环节是将前面sep环节生成的变量抽取版的harness中的独立变量抽取出来形成一个列表（也就是独立变量分离出来方便后续变异）后续对sep这一步中被标记为初始化变量的部分用一个while循环将其包起来，在这个while循环中对提取到的变量（包括变量和malloc这类内存分配操作）进行模仿AFL中havoc逻辑的变异

之后按照一个逻辑采样harness列表中的5个harness进行并行的模糊测试