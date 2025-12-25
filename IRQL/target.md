# 项目需求文档 (PRD): IRQL

## 文档信息
- **文档版本**: V1.2 (TS 重构完整版)
- **项目代号**: Project Dopamine / IRQL
- **文档状态**: 核心设计完成
- **起草日期**: 2025-xx-xx
- **作者**: [您的名字] (Founder/CTO)
- **技术核心**: Vue 3 (TypeScript) + Golang + Redis

## 1. 项目概述 (Executive Summary)

### 1.1 背景与痛点
学习（特别是内核、逆向、底层开发）极其痛苦，反馈路径过长。传统的 StackOverflow 仅能解决工具属性，无法解决情绪属性。

### 1.2 产品愿景
将程序员的学习过程“MMORPG化”。  
通过即时反馈、赛季竞技、和“不比高低比奇特”的社区文化，消除学习的痛苦，实现“成瘾性学习”。

### 1.3 核心哲学
- **确定性高回报**: 只要写代码、发帖、纠错，进度条就一定会涨。
- **高概率惊喜**: 随机触发的成就、社区投票带来的意外走红。

## 2. 用户角色 (User Personas)

| 角色 | 描述 | 核心需求 |
|------|------|----------|
| 内核/底层修仙者 | 攻克 Windows 内核等高难领域的孤独者。 | 需要被看见，需要把“蓝屏”转化为勋章。 |
| 二次元极客 | 喜欢 VTuber、追求 UI 美感的程序员。 | 需要精美的看板、二次元皮肤和有趣的社交。 |
| 榜单猎人 | 竞技心极强，追求赛季第一。 | 需要公平、实时、多维度的天梯系统。 |

## 3. 功能需求说明 (Functional Requirements)

### 3.1 账户与“进化”系统
- **身份体系**:
  - 支持 GitHub、邮箱、手机号登录。
  - 六维战力面板 (VueTS 渲染): 包含代码力(持久)、重构力(优雅)、修仙力(凌晨活跃)、社交力(获赞)、防御力(Bug率)、探索力(新技术)。
- **数字生命 (Avatar)**:
  - 初始为“数字细胞”，随等级进化为“机械体/皮套人”。
  - 支持加载 Live2D 模型（你喜欢的小姐姐/VTuber）。

### 3.2 竞技排行榜 (重构版：不卷总量卷趣味)
- **赛季机制 (Seasons)**: 每 3 个月一次新旧赛季交替。
- **多维度天梯**:
  - “最优雅代码”榜: 社区投票选出本周最艺术的代码片段。
  - “最诡异 Bug”榜: 分享并投票选出离奇的调试经历（如蓝屏代码分析）。
  - “考古发现”榜: 挖掘旧版文档或源码中的有趣遗迹。
  - 传统战力榜: 包含总榜及各个子频道（内核、Web安全、AI等）的积分榜。

### 3.3 社区交互 (Realms & Guilds)
- **分区 (Realms)**:
  - 内核特化区: 支持上传 Dump 文件分析报告，自动匹配“蓝屏死士”勋章。
  - 代码锐评: 行内评论功能，让代码 Review 变成弹幕吐槽。
- **公会 (Guilds)**: 用户自建频道，拥有独立的小型天梯。

### 3.4 激励机制 (Gamification)
- **积分获取**: 每日签到、有效发帖、代码纠错、GitHub Commit。
- **成就系统**: 参考小米运动徽章，如“连轴转 24h”、“首个 IRP 完成”、“BSOD 终结者”。

## 4. 技术架构 (Technical Architecture)

### 4.1 技术栈选型
- **前端 (Client)**: Vue 3 + TypeScript + Vite。
  - Pinia: 管理用户状态与实时积分。
  - Shiki: 高性能代码高亮。
  - Capacitor: 将 Vue 代码打包为移动端 App。
- **后端 (Backend)**: Golang (Gin/Go-Zero)。
- **存储 (Storage)**: PostgreSQL (持久化) + Redis (核心排行榜 ZSET)。

### 4.2 架构图
*(架构图待补充)*

## 5. 数据结构设计 (Database Schema)

### 5.1 用户核心表 (Users)
```sql
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(50) DEFAULT '代码新兵', -- 称号
    avatar_id INT, -- 对应虚拟形象/皮套ID
    total_score BIGINT DEFAULT 0,
    radar_data JSONB, -- 存储六维图实时数据
    created_at TIMESTAMP DEFAULT NOW()
);
```

### 5.2 赛季排行榜 (Rankings)
```sql
CREATE TABLE rankings (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id),
    season_id INT, -- 如 202501
    category_id INT, -- 0-总榜, 1-内核, 2-Web安, 3-AI
    rank_score INT DEFAULT 0,
    weekly_change INT, -- 周排名变动
    updated_at TIMESTAMP
);
```

## 6. 实施路线图 (Roadmap)

### 阶段一：MVP (多巴胺基座)
- [ ] 后端实现基于 Redis 的实时积分更新接口。
- [ ] 前端用 VueTS 实现“战力实时看板”。
- [ ] 实现最基础的“内核区”发帖与点赞。

### 阶段二：游戏化增强
- [ ] 引入 Live2D 虚拟伴侣 挂件。
- [ ] 开发“代码选美”投票插件。
- [ ] 实现赛季结算逻辑与徽章发放。

### 阶段三：全端爆发
- [ ] 完成 Capacitor 移动端适配。
- [ ] 接入 GitHub Webhook，实现提交代码自动加分。