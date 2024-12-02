#include <iostream>
#include <Windows.h>
#include <Tlhelp32.h>
#include <QApplication>
#include <QPushButton>
#include <QWidget>
#include <QComboBox>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QLineEdit>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QApplication>
#include <QVBoxLayout>
#include <QWidget>

struct QProcessInfo {
    DWORD pid{};
    QString processName;
};

Q_DECLARE_METATYPE(QProcessInfo)


class FileDropLineEdit : public QLineEdit {

public:
    explicit FileDropLineEdit(QWidget *parent = nullptr) : QLineEdit(parent) {
        this->setAcceptDrops(true);
    }

protected:
    void dragEnterEvent(QDragEnterEvent *event) override {
        if (event->mimeData()->hasUrls()) {
            event->acceptProposedAction();
        }
    }

    void dropEvent(QDropEvent *event) override {
        QList<QUrl> urls = event->mimeData()->urls();
        if (!urls.isEmpty()) {
            QString filePath = urls.first().toLocalFile();
            if (filePath.endsWith(".dll")) {
                setText(filePath);
            }
        }
    }
};

class InjectMainWidget : public QWidget {

public:
    explicit InjectMainWidget(QWidget *parent = nullptr) : QWidget(parent) {
        cbProcessList = new QComboBox(this);
        pbRefreshProcessList = new QPushButton("刷新", this);
        teDllPath = new FileDropLineEdit(this);
        pbInjectDll = new QPushButton("注入", this);

        auto *layout = new QVBoxLayout(this);

        cbProcessList->setMaxVisibleItems(25);

        teDllPath->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        teDllPath->setFixedHeight(30);

        layout->addWidget(cbProcessList);
        layout->addWidget(pbRefreshProcessList);
        layout->addWidget(teDllPath);
        layout->addWidget(pbInjectDll);

        connect(pbRefreshProcessList, &QPushButton::clicked, this, &InjectMainWidget::refreshProcessList);
        connect(pbInjectDll, &QPushButton::clicked, this, &InjectMainWidget::injectFunction);

        refreshProcessList();
    }

private slots:

    void refreshProcessList() {
        cbProcessList->clear();

        HANDLE hProcessSnap = nullptr;
        PROCESSENTRY32 pe32 = {0};
        pe32.dwSize = sizeof(PROCESSENTRY32);

        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        while (Process32Next(hProcessSnap, &pe32)) {
            QString processName = QString::fromWCharArray(pe32.szExeFile);
            QString pid = QString("%1").arg(pe32.th32ProcessID);

            QProcessInfo processInfo;
            processInfo.pid = pe32.th32ProcessID;
            processInfo.processName = processName;

            cbProcessList->addItem(QString("%1[%2]").arg(QString::fromWCharArray(pe32.szExeFile), pid),
                                   QVariant::fromValue(processInfo));
        }
    }

    static BOOL injectDll(DWORD pid, const QString &dllPath) {
        HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        LPVOID pRemoteProcessAdress = VirtualAllocEx(
                hTargetProcess,
                nullptr,
                dllPath.length() * 2,
                MEM_COMMIT,
                PAGE_READWRITE
        );
        auto dll = reinterpret_cast<const wchar_t *>(dllPath.utf16());
        SIZE_T dwWriteSize = 0;
        BOOL bRet = WriteProcessMemory(hTargetProcess, pRemoteProcessAdress, dll,
                                       dllPath.length() * 2, &dwWriteSize);
        HMODULE hModule = GetModuleHandle(L"kernel32.dll");

        auto loadLibraryWAddr = (LPTHREAD_START_ROUTINE) GetProcAddress(hModule, "LoadLibraryW");

        HANDLE hRemoteThread = CreateRemoteThread(
                hTargetProcess,
                nullptr,
                0,
                (LPTHREAD_START_ROUTINE) loadLibraryWAddr,
                pRemoteProcessAdress,
                NULL,
                nullptr
        );

        WaitForSingleObject(hRemoteThread, 1000);
        DWORD htErrCode = GetLastError();
        if (htErrCode != 0) {
            printf("CreateThreadHandle Error, code: %d\n", htErrCode);
            return 0;
        }

        VirtualFreeEx(hTargetProcess, pRemoteProcessAdress, 1, MEM_DECOMMIT);

        return 1;
    }

    QString getDllPath() {
        QString dllPath = teDllPath->text();
        if (!dllPath.isEmpty()) {
            return dllPath;
        }

        QString filePath = QFileDialog::getOpenFileName(
                nullptr,
                "选择dll文件",
                "",
                "DLL文件 (*.dll);;所有文件 (*)"
        );

        return filePath;
    }

    void injectFunction() {
        QVariant processInfoVariant = cbProcessList->currentData();
        auto processInfo = processInfoVariant.value<QProcessInfo>();

        auto filePath = getDllPath();
        if (filePath.isEmpty()) {
            QMessageBox::critical(
                    nullptr,
                    "错误",
                    "请选择dll文件。"
            );
            return;
        }

        if (injectDll(processInfo.pid, filePath)) {
            QMessageBox::information(nullptr, "提示", "注入成功：" + filePath);
        } else {
            QMessageBox::critical(
                    nullptr,
                    "错误",
                    "注入失败，请检查文件或权限。"
            );
        }
    }

private:
    QComboBox *cbProcessList;
    QPushButton *pbRefreshProcessList;
    FileDropLineEdit *teDllPath;
    QPushButton *pbInjectDll;
};


int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    InjectMainWidget widget;
    widget.setWindowTitle(QString("DLL注入器 v1.1"));
    widget.setFixedWidth(400);
    widget.setFixedHeight(150);

    widget.show();
    return QApplication::exec();
}
