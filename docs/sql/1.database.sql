/*
* youlai-cloud 微服务模板 SQL 脚本
* MySQL8.x版本
*/

-- ----------------------------
-- 系统管理数据库
-- ----------------------------
CREATE DATABASE IF NOT EXISTS youlai_system DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_general_ci;

-- ----------------------------
-- OAuth2数据库
-- ----------------------------
CREATE DATABASE IF NOT EXISTS oauth2_server DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_general_ci;