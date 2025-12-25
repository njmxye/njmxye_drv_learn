# IRQL 项目文档 V2.0 (丐版)

## 1. 项目概述

### 1.1 项目目标
为程序员提供一个简洁的技术学习与交流平台，专注于内核、逆向、底层开发等硬核技术领域。

### 1.2 核心功能
- 技术文章发布与讨论
- 代码片段分享
- 基础积分系统
- 简单排行榜

## 2. 系统架构

### 2.1 技术栈
- **前端**: Vue 3 + TypeScript
- **后端**: Golang (Gin框架)
- **数据库**: PostgreSQL + Redis
- **部署**: Docker

### 2.2 架构图
```
用户 -> 前端(Vue) -> 后端(Golang) -> 数据库(PostgreSQL/Redis)
```

## 3. 核心功能

### 3.1 用户系统
- 注册/登录 (GitHub OAuth + 邮箱)
- 用户资料页
- 基础积分统计

### 3.2 内容系统
- 文章发布/编辑/删除
- 代码片段分享
- 评论功能
- 点赞/收藏

### 3.3 积分系统
- 发布文章: +10分
- 发布代码: +5分
- 获得点赞: +1分/个
- 发表评论: +2分

### 3.4 排行榜
- 总积分榜
- 周活跃榜
- 技术分类榜 (内核/逆向/Web安全等)

## 4. 数据库设计

### 4.1 用户表
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE,
    github_id VARCHAR(100),
    total_score INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### 4.2 文章表
```sql
CREATE TABLE posts (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    category VARCHAR(50), -- 内核/逆向/Web安全等
    view_count INT DEFAULT 0,
    like_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### 4.3 代码片段表
```sql
CREATE TABLE code_snippets (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    title VARCHAR(200) NOT NULL,
    code TEXT NOT NULL,
    language VARCHAR(50), -- C/C++/Go/Python等
    description TEXT,
    like_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## 5. API接口设计

### 5.1 用户相关
- `POST /api/auth/login` - 用户登录
- `POST /api/auth/register` - 用户注册
- `GET /api/users/{id}` - 获取用户信息
- `GET /api/users/{id}/posts` - 获取用户文章

### 5.2 内容相关
- `GET /api/posts` - 获取文章列表
- `POST /api/posts` - 创建文章
- `GET /api/posts/{id}` - 获取文章详情
- `POST /api/posts/{id}/like` - 点赞文章

### 5.3 排行榜
- `GET /api/rankings/total` - 总积分榜
- `GET /api/rankings/weekly` - 周活跃榜
- `GET /api/rankings/category/{category}` - 分类榜

## 6. 开发计划

### 阶段一: 基础功能 (2周)
- 用户系统实现
- 文章发布功能
- 基础UI界面

### 阶段二: 核心功能 (3周)
- 代码片段分享
- 评论系统
- 积分系统
- 基础排行榜

### 阶段三: 优化完善 (2周)
- 性能优化
- 错误处理
- 部署上线

## 7. 部署要求

### 7.1 服务器配置
- CPU: 2核以上
- 内存: 4GB以上
- 存储: 50GB以上

### 7.2 依赖服务
- PostgreSQL 12+
- Redis 6+
- Nginx (反向代理)

## 8. 维护计划

### 8.1 日常维护
- 数据库备份
- 日志监控
- 性能监控

### 8.2 版本更新
- 每月一次小版本更新
- 每季度一次功能更新