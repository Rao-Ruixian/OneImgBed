# **OneImgBed - 可能是最简陋但勉强能用的PHP图床**  

**⚠️ 警告：本项目由AI生成，代码质量堪忧，安全漏洞可能比功能还多，请谨慎使用！**  

![PHP](https://img.shields.io/badge/PHP-%3E%3D7.0-blue?style=for-the-badge&logo=php&logoColor=white)  ![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)  ![Security](https://img.shields.io/badge/Security-¯\_(ツ)_/¯-red?style=for-the-badge)  

## **💩 项目介绍**  

一个**勉强能用**的、由**一个PHP文件构成**的图床系统（所以叫one嘛），由AI生成，代码风格**极其狂野**，安全防护**全靠运气**，功能**简陋到令人发指**。  

• **🚀 核心功能**：上传图片、删除图片（是的，就这一个）  
• **🔒 安全防护**：密码登录（但可能被爆破）  
• **📦 存储方式**：直接丢服务器上（别问备份，问就是没有）  
• **⚡ 性能优化**：PHP原生（慢就慢吧，反正又不是不能用）  

## **🤡 为什么用这个？**  

• **只有一个php文件**（是的，没错）  
• **你懒得自己写代码**（反正AI帮你写好了）  
• **你想体验一下什么叫"屎山代码"**（不欢迎PR优化）  
• **你不在乎安全**（反正数据不值钱）  
• **你只是想找个地方存点猫猫图**（这个真可以）  

## **🛠️ 安装指南（如果你真的想用）**  

1. **下载 `index.php`**（就这一个文件，够简单吧？）  
2. **改配置文件**（建议设置20+长强密码，不然会被爆破）  
    ```php
   define('UPLOAD_DIR', 'p');              // 上传目录
   define('PASSWORD_HASH', '这里填写输出的hash值'); //密码hash值
   define('MAX_FILE_SIZE', 20 * 1024 * 1024); // 最大文件大小 20MB
   // 其他配置...
   ```
3. **扔到服务器上**（Apache/Nginx都行，PHP能用就行）  
4. **访问网页**（祈祷它不会报错，祈祷没有木马入侵）


### 密码生成

使用以下PHP命令生成密码哈希:
```php
echo password_hash('your_password', PASSWORD_BCRYPT);
```
## **🚨 已知问题（太多了，随便列几个）**  

✅ **不支持数据库**（文件直接存服务器，删库跑路？不存在的！）  
✅ **没有缩略图**（原图加载，流量爆炸？那是你的问题！）  
✅ **没有API**（想用程序上传？自己写吧！）  
✅ **没有多用户**（一人吃饱，全家不饿）  
✅ **安全性低**（服务器炸了？自求多福！）  

## 截图预览

![登录界面](https://github.com/user-attachments/assets/45d2cf6b-aa01-4ec6-89c9-5de4d723cbc7)
![上传界面](https://github.com/user-attachments/assets/8e1d1e51-9e2b-4ac1-8727-c643f553cc87)
![图片管理](https://github.com/user-attachments/assets/4ccd84a5-989f-4827-a086-edc8e0cb0705)

## **🤝 贡献指南**  

欢迎提交**PR**（如果你能看懂这坨代码的话），或者**提Issue**（但我不一定修）。  

## **📜 许可证**  

**MIT**（随便用，炸了别找我）  

## **😎 作者**  

**Deepseek + 懒得优化的人类**（GitHub: [Rao-Ruixian](https://github.com/Rao-Ruixian)）  

---

### **🎉 总结**  

**能用，但别指望太多。** 适合**个人临时存图**，**不适合生产环境**。  

**如果你真的用了，记得备份！**（虽然我猜你不会）  

**🚀 祝你好运！**（希望你的服务器不会炸或者被人上传一堆奇怪的php东西）
