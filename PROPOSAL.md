# moonbin 项目申报书

## 1 项目名称

moonbin — 纯 MoonBit 的二进制格式解析与 x86-64 反汇编库

## 2 项目简介

我做逆向和安全研究，天天和 PE/ELF 打交道，但 MoonBit 生态里没有一个能直接读可执行文件的库：要么自己手写报文/头解析，要么桥接外部进程，后者在 wasm 目标上根本走不通。moonbin 就是补这一层：零 FFI，同一份 MoonBit 代码编译到 native / wasm / js，读真实 PE/ELF，走节表/符号/导入/导出，反汇编 `.text`。

它不猜。每个读取都带边界检查，畸形输入返回 Truncated/BadMagic/Invalid，不 panic 也不编造字段；子集外的 opcode 如实报 `.byte` 继续，不静默截断。正确性不靠自说自话，对着参考工具逐字节核：PE 对 objdump、ELF 对 readelf、反汇编对 capstone。

## 3 项目方向与通用性

方向：开发者工具 / 基础库（填补 MoonBit 在二进制分析基础设施上的空白）。其它生态的成熟方案：goblin / LIEF / pefile（格式解析）、capstone / iced-x86（反汇编）。MoonBit 侧目前没有功能对等的库。

通用性：解析能力以库 API 暴露（`pe::parse` / `elf::parse` / `disasm::decode`），不绑应用场景。同一个库既能做命令行分析工具，也能编译进浏览器做在线 RE 演示，或作为固件/恶意样本静态分析的第一级。核心不依赖文件系统与网络（native 文件层单独可选）。

## 4 预期使用场景

1. 命令行快速体检：`moonbin info/sections/imports/exports <file>`，不装重型工具就能看一个二进制的结构、导入表和导出表。
2. 反汇编抽查：`moonbin disasm <file> --count N --json`，对 `.text` 做子集反汇编，输出可进脚本做批量比对。
3. 浏览器端 RE 演示：编译到 wasm，把解析/反汇编放进网页，拖入文件即看结构，无需后端。
4. 安全/固件分析底座：作为静态分析第一级，先解析容器与节表，再交给上层做字符串/导入/熵分析。

## 5 拟实现的核心功能

已完成：PE32/PE32+（DOS→NT→COFF→可选头→节表→导入/导出/符号，RVA→文件偏移）；ELF32/64 双端序（头、段、节、symtab/dynsym、dynamic）；x86-64 常用整数+SSE 子集（前缀/REX/ModR/M/SIB/disp/imm，长度精确）；格式自动识别；CLI 六个子命令 + `--json`；62 个单元测试；三份参考工具交叉核对脚本；native 与 wasm 双构建；`--deny-warn` 零告警。

## 6 原创性

原创。算法（PE/COFF、ELF 规范、x86 编码）为公开规范的独立实现，未复制任何现有实现代码。

## 7 移植或参考说明

不适用，非移植。依赖仅 `moonbitlang/x`（Apache-2.0），只用未修改公开 API。本项目 Apache-2.0。

## 8 GitHub 仓库链接

https://github.com/NaIWaniubi/moonbin — 连续提交，CI 含 check(--deny-warn)/test/双构建/三交叉核对。