@echo off
echo ========================================
echo  启动 EC-VRF 公平性验证服务
echo ========================================
echo.
echo [1/2] 安装依赖...
pip install -r requirements.txt
echo.
echo [2/2] 启动后端服务...
python app.py
pause