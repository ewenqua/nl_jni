
cd build/intermediates/classes/debug
javah -classpath . -d myjni -jni com.android.server.mia.Interface

android:sharedUserId="android.uid.system"

adb shell cat proc/kmsg
adb shell dmesg -c
adb shell dmesg -w

adb install -r ~/Wesnoth/wj_firewall/FireWallSample/fireWallSample/release/fireWallSample-release.apk
adb install -r D:\4_Online_Source\CSDK_Online\tools\CSDKFireWall\fireWallSample\release\fireWallSample-release.apk


echo "# nl_jni" >> README.md
git init
git add README.md
git commit -a -m "first commit"
git remote add origin https://github.com/ewenqua/nl_jni.git
git push -u origin master

