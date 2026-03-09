# StorageCheck

StorageCheck 是一个本地硬盘快照工具，适合盯住 `C:\` 或任意目录，记录“这次多了多少、哪个文件夹变大了”。

## 现在已经做好的能力

- 手动扫描。
- 每隔 N 小时自动扫描。
- 每天固定时间自动扫描。
- 支持扫描盘符根目录，例如 `C:\`，也支持扫描任意自定义文件夹。
- 默认按层保存前 N 层目录，方便长期记录历史；也支持完整保存所有文件和目录。
- 每次扫描都会把结果写进 SQLite，后续可以切换历史快照查看。
- 目录浏览默认按体积从大到小排序，并显示占父级百分比。
- 点进任意目录或文件后，可以看到这个路径在历史扫描中的体积曲线。

## 技术实现

- 后端：FastAPI
- 历史库：SQLite
- 定时：APScheduler
- 前端：本地静态页面，无需额外前端构建

## 目录说明

- `start.py`：启动本地服务并自动打开浏览器。
- `start.bat`：Windows 下双击即可运行。
- `storagecheck/main.py`：API 和页面入口。
- `storagecheck/scanner.py`：硬盘扫描核心。
- `storagecheck/db.py`：扫描目标、扫描记录、节点历史的存储。
- `storagecheck/static/`：界面样式和交互脚本。
- `tests/test_scanner.py`：扫描深度逻辑的基础测试。

## 使用方法

### 方式一：直接双击

双击 `start.bat`。
第一次运行会自动创建 `.venv`，安装依赖，再启动程序。

### 方式二：命令行启动

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python start.py
```

如果浏览器没有自动弹出，可以手动打开 `http://127.0.0.1:8765`。

## 建议怎么用

1. 先添加一个目标，例如 `C:\`。
2. 如果你主要想长期追踪“哪个目录突然变大”，建议选 `按层保存`，层级先用 `6`。
3. 如果你要做一次非常细的文件级排查，可以临时建一个 `完整保存` 的目标。
4. 先手动扫一次，生成第一份快照。
5. 后面就可以在右侧切换不同时间点的扫描结果，对比目录变化。

## 关于“按层保存”

例如设置成 6 层：

- 数据库只保存前 6 层的节点，历史库不会膨胀得太快。
- 第 6 层目录的大小依然会把更深层内容累加进去，所以体积是准确的。
- 只是更深层不会继续展开显示。

## 注意事项

- 某些系统保护目录会因为权限不足而跳过，扫描不会中断。
- `完整保存` 在大盘上会写入很多记录，明显比按层保存更重。
- 现在的自动扫描依赖程序处于运行状态；如果你后面希望它彻底接入 Windows 计划任务，我也可以继续帮你补上。
- 数据库会在首次运行后创建到 `data/storagecheck.db`。

## 运行测试

```powershell
python -m unittest tests.test_scanner
```

## NTFS MFT fast path

- For NTFS drive roots like `C:\`, StorageCheck now tries a Windows MFT fast scan before the old recursive walk.
- This fast path needs Administrator privileges. On Windows, launch with `start-admin.bat`.
- If the target is not a drive root, not NTFS, or the app is not elevated, StorageCheck falls back to the existing recursive scanner automatically.
- The UI now shows which scan engine was used, plus MFT phase progress when available.
