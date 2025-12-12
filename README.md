# LPG-s-Anit-PCDN
https://img.shields.io/github/stars/Windows-LPG/LPG-s-Anit-PCDN
https://img.shields.io/github/license/Windows-LPG/LPG-s-Anit-PCDN
https://img.shields.io/badge/python-3.x-blue.svg

防止恶意软件窃取家庭宽带上传带宽 | Prevent Malware from Stealthily Using Broadband Upload Bandwidth

📖 简介 / Introduction
这是一个用于检测和阻止恶意软件/流氓软件滥用家庭宽带上传带宽的工具。某些中国软件（如一些视频播放器、云盘、下载工具等）会在后台偷偷使用用户的宽带上传流量，参与P2P CDN网络，导致用户网络变慢、流量消耗增加。

This tool is designed to detect and prevent malicious software/rogue applications from abusing home broadband upload bandwidth. Some Chinese software (such as certain video players, cloud drives, download tools, etc.) secretly use users' upload traffic in the background to participate in P2P CDN networks, resulting in slower internet speeds and increased data consumption.

✨ 功能特性 / Features
🔍 实时监控 - 监控网络连接，识别可疑的P2P CDN活动

🛡️ 自动阻断 - 自动阻止被识别为恶意的P2P流量

📊 流量分析 - 提供详细的流量统计和报告

🔔 通知提醒 - 发现可疑活动时发送通知

⚙️ 可配置规则 - 支持自定义规则和例外列表

🚀 快速开始 / Quick Start
安装依赖 / Install Dependencies
bash
pip install -r requirements.txt
运行程序 / Run the Tool
bash
python main.py
配置说明 / Configuration
编辑 config.yaml 文件调整设置

根据需要修改规则文件 rules.json

运行监控服务

📁 项目结构 / Project Structure
text
LPG-s-Anit-PCDN/
├── main.py              # 主程序入口
├── config.yaml          # 配置文件
├── rules.json           # 规则定义文件
├── requirements.txt     # Python依赖
├── LICENSE             # GPL v3许可证
└── README.md           # 项目说明
🤝 如何贡献 / Contributing
欢迎提交Issue和Pull Request！以下是贡献方式：

🐛 报告问题 - 在Issues页面报告bug或提出建议

💡 提交功能请求 - 描述你希望添加的新功能

🔧 提交代码 - Fork项目并提交Pull Request

📝 改进文档 - 帮助改进文档或翻译

📄 许可证 / License
本项目采用 GNU General Public License v3.0 开源协议。

This project is licensed under the terms of the GNU GPLv3 license.

查看完整许可证 | View Full License

🌟 Star历史 / Star History
https://api.star-history.com/svg?repos=Windows-LPG/LPG-s-Anit-PCDN&type=date&theme=dark

🙏 致谢 / Acknowledgments
使用 Python 编写

主要开发辅助：DeepSeek AI

人工审核和修改：项目维护者

感谢所有贡献者和用户的支持！

📬 联系 / Contact
GitHub Issues: 问题反馈

项目主页: LPG's Anti-PCDN

⚠️ 免责声明 / Disclaimer
本工具仅供学习和研究使用，请勿用于非法用途。使用本工具产生的任何后果由使用者自行承担。

This tool is for educational and research purposes only. Do not use it for illegal activities. Users are responsible for any consequences resulting from the use of this tool.

如果觉得这个项目有用，请给个 ⭐ Star 支持一下！
## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Windows-LPG/LPG-s-Anit-PCDN&type=date&legend=top-left)](https://www.star-history.com/#Windows-LPG/LPG-s-Anit-PCDN&type=date&legend=top-left)
感谢所有送出star的用户！
