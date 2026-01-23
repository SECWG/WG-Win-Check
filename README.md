## 简介

WG-Win-Check 是一款基于原生 Win32 API 实现的轻量级的 Windows 应急响应辅助工具，目前 64 位版本大小仅 615Kb，旨在以轻量便捷的特性，通过多维度的系统常规排查，能够有效帮助安全人员快速识别恶意进程、可疑启动项、异常网络连接等安全风险。

## 核心功能

### 用户排查

枚举系统所有用户账户（包括隐藏用户）基础信息、识别克隆账户和异常权限。
<img width="1178" height="489" alt="image" src="https://github.com/user-attachments/assets/fb9c36c2-8772-4074-a8fd-a4c20dd0e65b" />


### 进程排查

监控列举系统所有进程，展示基础进程信息字段，支持按进程类型、签名、关键字过滤。提供进程树、DLL 模块、执行文件 hash、在线验证、签名校验以及进程结束操作。
<img width="1186" height="495" alt="image" src="https://github.com/user-attachments/assets/2c77d844-80bc-4b2c-9056-1b1262673636" />
<img width="1242" height="648" alt="image" src="https://github.com/user-attachments/assets/c9a76487-de0c-4bad-b9cd-310ce568f0ac" />

### 网络连接排查

监控所有 TCP/UDP 连接 ，展示基础连接信息及关联进程，支持按协议、状态、外联、关键字进行快速过滤筛选，提供一键提取所有外联 IP。
<img width="1245" height="650" alt="image" src="https://github.com/user-attachments/assets/cab25d08-fa68-4f68-91bc-5309ade843ef" />


### 启动项排查

扫描系统常见启动项，包括：注册表启动项（Run、RunOnce、RunServices）、启动文件夹、Winlogon 劫持、IFEO（映像劫持）等其他驻留手段。
<img width="1245" height="646" alt="image" src="https://github.com/user-attachments/assets/6895fd92-6ebf-4eea-bb13-bf31a9d5297f" />


### 服务排查

枚举所有系统服务，可基于服务类型、签名、启动类型、服务状态进行过滤，包含签名校验及其他基础风险高亮规则，同时可快捷管理服务。
<img width="1243" height="647" alt="image" src="https://github.com/user-attachments/assets/c4ef2218-fe1a-4fc4-9768-f61e7b8d619b" />


### 计划任务排查

列举所有计划任务，展示基础信息包括执行程序、文件路径、运行实际等，支持类型(系统/用户)、运行状态、关键字快速过滤。提供基础计划任务暂停、运行、删除等快捷操作。
<img width="1244" height="646" alt="image" src="https://github.com/user-attachments/assets/7c1ed08b-46fe-4662-9eb0-72839b2acd74" />


### 文件排查

扫描常见的恶意文件落地目录包括下载、临时目录，过滤常见的恶意文件落地类型，支持自定义扫描路径如微信、飞书文件下载路径的扫描。
<img width="1242" height="649" alt="image" src="https://github.com/user-attachments/assets/8c17f6ae-133c-4331-892f-912676520aad" />


### 事件日志排查

提供常见事件类型包括登录、进程创建、日志清除的排查，以及快速关联打开操作。
<img width="1248" height="651" alt="image" src="https://github.com/user-attachments/assets/b245fb92-b0e4-463f-bc09-1c6411b08b31" />


### 威胁检索

基于 IOC 进程内存特征的威胁检索，检索上下文，便于快速定位快速定位可疑进程。
<img width="1182" height="511" alt="image" src="https://github.com/user-attachments/assets/7d7fb287-5995-4f50-81a8-159158972c2c" />


## 其他特点

-   内置基础风险判定规则，基于规则进行高亮标注，一目了然，便于快速分析定位。
    
-   原生 Win32 API 实现，无第三方依赖。
    
-   扫描结果 CSV 导出。
    

## 系统要求

-   **操作系统**：Windows 10 / 11，目前仅两个系统进行测试，原则上其他版本皆可支持。
    
-   **架构**：目前仅 x64。
    
-   **权限**：建议以管理员权限运行，否则影响扫描结果以及部分功能。
    
-   **依赖**：无需安装任何运行库，开箱即用。
    

## 获取方式

### 下载地址
    
-   Github 下载：[https://github.com/SECWG/WG-Win-Check/releases](https://github.com/SECWG/WG-Win-Check/releases)
    

### 授权说明

基于离线安全、轻量便捷性，工具使用简单的离线授权校验机制，但授权可免费申请获取，前往本站[授权中心](https://secwg.com/license-center)获取授权码后方可使用。

有兴趣、有能力者可自行破解进行小范围使用，但请尊重开发者，勿广泛传播即可。

## 更新日志

### v1.0.0 (2025-01-18)

✨ 首次发布:

1.  用户排查 - 枚举系统用户账户，识别隐藏用户和克隆账户
    
2.  进程排查 - 监控系统进程，支持进程树查看、DLL分析、签名验证和在线威胁查询
    
3.  网络连接排查 - 监控TCP/UDP连接，快速过滤方式
    
4.  启动项排查 - 全面扫描注册表启动项、启动文件夹、IFEO劫持等多种启动方式
    
5.  服务排查 - 枚举系统服务，检测异常服务
    
6.  计划任务排查 - 扫描系统计划任务，显示任务状态、触发器和执行程序
    
7.  文件排查 - 扫描指定目录常见落地文件类型，支持自定义路径
    
8.  事件日志排查 - 分析Windows安全事件日志，筛选登录失败、权限提升等关键事件
    
9.  威胁检索 - 基于进程内存特征的威胁检索
