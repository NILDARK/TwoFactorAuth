from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *
import re
import uuid
import socket
import smtplib
import rstr
import db
from creds import *
import hashlib


class Ui_loginSection(QWidget):
    def isConnected(self):
        '''
        Checks internet connection using socket
        rtype: Boolean
        '''
        try:
            socket.create_connection(("1.1.1.1", 53))
            return True
        except OSError:
            pass
        return False

    def getMAC(self):
        '''
        Returns MAC address of the machine
        rtype: str
        '''
        return (':'.join(re.findall('..', '%012x' % uuid.getnode())))

    def exit(self):
        '''
        Exit Login Window
        rtype: None
        '''
        self.loginSec.close()

    def switchUserLogin(self):
        '''
        Switch to Login Section after clearing previous fields
        rtype: None
        '''
        self.loginCred1.clear()
        self.loginCred2.clear()
        self.signUpCred0.clear()
        self.signUpCred1.clear()
        self.signUpCred2.clear()
        self.signUpCred3.clear()
        self.signUpCred4.clear()
        self.userLoginSection.setVisible(True)
        self.userRegisterSection.setVisible(False)

    def switchUserRegister(self):
        '''
        Switch to User Registration Section after clearing previous fields
        rtype: None
        '''
        self.loginCred1.clear()
        self.loginCred2.clear()
        self.signUpCred0.clear()
        self.signUpCred1.clear()
        self.signUpCred2.clear()
        self.signUpCred3.clear()
        self.signUpCred4.clear()
        self.userLoginSection.setVisible(False)
        self.userRegisterSection.setVisible(True)

    def validateUsername(self, username):
        '''
        Validates username availiblity and makes sure username is not already in use
        Returns an array [isValid, reason_if_not]
        rtype: array -> [boolean,str]
        '''
        err = ""
        if(username == ""):
            err = "Username Should not be blank.\n"
        if(len(username) < 3):
            err += "Username Should be of minimum of length 3.\n"
        if(" " in username):
            err += "Username should not contain spaces.\n"
        x = re.search("[a-zA-Z]", username)
        if(x == None):
            err += "Username must contain atleast one alphabet.\n"
        if(err != ""):
            return [False, err]
        else:
            return [True, err]

    def getSignUpCreds(self):
        '''
        Gets data from input fields of Register Section and process it. If all is good, proceeds to add user in database. Also checks internet connection before any commit to database.
        rtype: None
        '''
        name = self.signUpCred0.text().strip()
        username = self.signUpCred1.text().strip()
        email = self.signUpCred2.text().strip()
        password = self.signUpCred3.text()
        cnfPassword = self.signUpCred4.text()
        err = ""
        if(name == ""):
            self.signUpCred0.clear()
            err += "Name field must not blank.\n"
        usrVal = self.validateUsername(username)
        if(not usrVal[0]):
            self.signUpCred1.clear()
            err += usrVal[1]
        passVal = self.validatePassword(password)
        if(not passVal[0]):
            self.signUpCred3.clear()
            err += passVal[1]
        if(email == "" or " " in email):
            self.signUpCred2.clear()
            err += "Invalid Format for Email.\n"
        if(err != ""):
            QMessageBox.critical(self, "Invalid Input Format Error", err)
            return

        if(cnfPassword != password):
            QMessageBox.critical(
                self, "Password Mismatch", "Entered Password does not match with above password.")
            self.signUpCred4.clear()
            return
        if(not self.isConnected()):
            QMessageBox.critical(
                self, "Connection Error", "No Internet Connection. Please after reconnecting.")
            return
        if(db.verifyUsername(username)[0]):
            QMessageBox.critical(self, "Error", "Username already exists.")
            self.loginCred1.clear()
            self.loginCred2.clear()
            return
        if(not self.isConnected()):
            QMessageBox.critical(
                self, "Connection Error", "No Internet Connection. Please after reconnecting.")
            return
        res = self.validateEmail(email, name)
        if(res == True):
            if(not self.isConnected()):
                QMessageBox.critical(
                    self, "Connection Error", "No Internet Connection. Please after reconnecting.")
                return
            if(db.addUser([name, username, password, email])):
                QMessageBox.information(
                    self, "Success", f"{name}, you are all set to login.")
                self.switchUserLogin()
                return
            else:
                QMessageBox.critical(
                    self, "Failure", "Something went wrong. Failed to register.")
                self.signUpCred0.clear()
                self.signUpCred1.clear()
                self.signUpCred2.clear()
                self.signUpCred3.clear()
                self.signUpCred4.clear()
                return
        elif(res == None):
            return
        else:
            QMessageBox.critical(self, "Verifcation Failure",
                                 "Email Verification Failed. Try Again Later.")
            self.signUpCred0.clear()
            self.signUpCred1.clear()
            self.signUpCred2.clear()
            self.signUpCred3.clear()
            self.signUpCred4.clear()
            return

    def sendEmail(self, to_email, OTP, name, msg=False):
        '''
        Sends verification code to given email using smtp protocol. Also used for two-factor Authentication. If msg is True it is for Two Factor Authentication.
        rtype: boolean 
        '''
        try:
            smtp = smtplib.SMTP('smtp.gmail.com', 587)
            smtp.starttls()
            smtp.login(sndemail, emailpass)
            if(msg):
                message = f"Hello {name},\n    Your OTP for two step verification is " + \
                    OTP+"\nFrom Team DarkDevs"
            else:
                message = f"Hello {name},\n    Your OTP for email verification is " + \
                    OTP+"\nFrom Team DarkDevs"
            message = 'Subject: {}\n\n{}'.format("Verification Code", message)
            smtp.sendmail("sndemail", to_email, message)
            smtp.quit()
            print("Email sent successfully!")
            return True
        except Exception as ex:
            print(ex)
            return False

    def validateEmail(self, email, name):
        '''
        Validates Email format and availiblity in database, if valid, verifies using verification code
        Returns True if valid & verified
        Returns False if verification failed
        Returns None if Something unexpected happens
        rtype: boolean/None 
        '''
        email_aval = db.checkEmailAvaibility(email)
        if(email_aval == None):
            QMessageBox.critical(
                self, "Connection Error", "Something went wrong. Please check internet connection and try later.")
            return None
        elif(email_aval == False):
            QMessageBox.critical(
                self, "Database Error", "Email Already in use. Try Using another email or login with username associated with it.")
            self.signUpCred2.clear()
            return None
        sent_vercode = rstr.xeger(r'[0-9]{6}')
        if(self.sendEmail(email, sent_vercode, name)):
            recv_vercode, done = QInputDialog.getText(
                self, 'Email Verification', f'Enter Verification Code sent to your email: {email}')
            if(done):
                if(recv_vercode == sent_vercode):
                    QMessageBox.information(
                        self, "Verification Success", "Email Verified Successfully.")
                    return True
                else:
                    QMessageBox.critical(
                        self, "Verification Failure", "Verification code mismatch. Try again.")
                    return None
            else:
                return False
        else:
            return False

    def validatePassword(self, password):
        '''
        Validates password format using regular expression.
        Returns array [isValid,error]
        rtype: array -> [boolean,str]
        '''
        err = ""
        if(password == ""):
            err = "Password Should not be blank.\n"
        if(len(password) < 8 or len(password) > 20):
            err += "Password Should be of minimum length 8 and maximum length is 20.\n"
        if(" " in password):
            err += "Password should not contain spaces.\n"
        r = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,20}$"
        x = re.search(r, password)
        if(x == None):
            err += "Password should contain atleast one alphabet, one digit, one uppercase, one lowercase and one special symbol.\n"
        if(err != ""):
            return [False, err]
        else:
            return [True, err]

    def getLoginCreds(self):
        '''
        Gets Login data from input fields of Login Section and process it. If login creds are valid and verified then it will proceed with Two Factor Auth if require else bypasses it. Two Factor Requirement is based on MAC Address of current machine requested to login from.
        rtype: None 
        '''
        username = self.loginCred1.text().strip()
        password = self.loginCred2.text().strip()
        mac = self.getMAC()
        err = False
        err1, err2 = "", ""
        if(username == ""):
            err = True
            self.loginCred1.clear()
            err1 = "Username should not be blank."
        if(password == ""):
            err = True
            self.loginCred2.clear()
            err2 = "Password should not be blank."
        if(err):
            QMessageBox.critical(self, "Invalid Input Error",
                                 (err1+"\n"+err2).strip())
            return
        res, twoStpReq = self.userLogin(username, password, mac)
        res1 = None
        if(res):
            if(twoStpReq == False):
                res1 = True
            else:
                email, name = db.getUserEmail(username)
                sent_vercode = rstr.xeger(r'[0-9]{6}')
                print(sent_vercode)
                if(self.sendEmail(email, sent_vercode, name, msg=True)):
                    recv_vercode, done = QInputDialog.getText(
                        self, 'Two Step Verification', f'Enter Verification Code sent to your email: {email}')
                    if(done):
                        if(recv_vercode == sent_vercode):
                            QMessageBox.information(
                                self, "Verification Success", "Good to go")
                            res1 = True
                        else:
                            QMessageBox.critical(
                                self, "Verification Failure", "Verification Code Mismatch. Try again.")
                            res1 = False
                    else:
                        res1 = None
                else:
                    res1 = False
        if(res1):
            print("Logged in")
            QMessageBox.information(self, "Success", "Logged In Successfully.")
            if(twoStpReq):
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Question)
                msg.setWindowTitle("Add to Trusted Device")
                msg.setText(
                    "Trusted Devices does not require two step verification, Do you want to add this device to Trusted Devices?")
                msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
                retval = msg.exec_()
                if(retval == 16384):
                    db.addDevice(username, mac)
                else:
                    pass
            self.exit()
        elif(res1 == None):
            return
        else:
            print("Login Failed")
            self.exit()
        return

    def forgotPassword(self, k):
        '''
        This is dummy function for forget password mechanism. As it is out of scope of current agenda.
        '''
        print("Forgot Password")
        pass

    def userLogin(self, username, password, mac):
        '''
        Validates and verifies the user. And also provides check for Two factor Auth using MAC Address of current machine.
        Returns [True, 0] if user is verified and two factor not required
        Returns [True, 1] if user is verified and two factor required
        Returns [False, None] if user is not verified
        rtype: array -> [boolean,int/None]
        '''
        if(self.isConnected() == False):
            QMessageBox.critical(
                self, "Connection Error", "No Internet Connection. Please after reconnecting.")
            return [False, None]
        res = db.verifyUsername(username)
        m = hashlib.sha256(password.encode())
        password = m.hexdigest()
        if(res[0]):
            if(res[1] == password):
                trust_check = db.isTrustedDevice(username, mac)
                if(trust_check):
                    return [True, 0]
                else:
                    return [True, 1]
            else:
                QMessageBox.critical(self, "Error", "Incorrect Password.")
                self.loginCred2.clear()
                return [False, None]
        else:
            QMessageBox.critical(self, "Error", "Username not found")
            self.loginCred1.clear()
            self.loginCred2.clear()
            return [False, None]

    def setupUi(self, loginSection):
        '''
        Integrates back-end functions to UI, and sets up UI components. This is mostly QtDesigner Generated code.
        rtype: None
        '''
        if not loginSection.objectName():
            loginSection.setObjectName(u"loginSection")
        loginSection.resize(1021, 303)
        self.loginSec = loginSection
        self.horizontalLayout_17 = QHBoxLayout(loginSection)
        self.horizontalLayout_17.setObjectName(u"horizontalLayout_17")
        self.widget = QWidget(loginSection)
        self.widget.setObjectName(u"widget")
        self.horizontalLayout_16 = QHBoxLayout(self.widget)
        self.horizontalLayout_16.setObjectName(u"horizontalLayout_16")
        self.userLoginSection = QGroupBox(self.widget)
        self.userLoginSection.setObjectName(u"userLoginSection")
        self.horizontalLayout_4 = QHBoxLayout(self.userLoginSection)
        self.horizontalLayout_4.setObjectName(u"horizontalLayout_4")
        self.horizontalSpacer = QSpacerItem(
            40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_4.addItem(self.horizontalSpacer)

        self.widget_2 = QWidget(self.userLoginSection)
        self.widget_2.setObjectName(u"widget_2")
        self.verticalLayout = QVBoxLayout(self.widget_2)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.verticalSpacer = QSpacerItem(
            20, 68, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout.addItem(self.verticalSpacer)

        self.widget_3 = QWidget(self.widget_2)
        self.widget_3.setObjectName(u"widget_3")
        self.horizontalLayout = QHBoxLayout(self.widget_3)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.loginCred1 = QLineEdit(self.widget_3)
        self.loginCred1.setObjectName(u"loginCred1")

        self.horizontalLayout.addWidget(self.loginCred1)

        self.verticalLayout.addWidget(self.widget_3)

        self.widget_4 = QWidget(self.widget_2)
        self.widget_4.setObjectName(u"widget_4")
        self.horizontalLayout_2 = QHBoxLayout(self.widget_4)
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.loginCred2 = QLineEdit(self.widget_4)
        self.loginCred2.setObjectName(u"loginCred2")
        self.loginCred2.setEchoMode(QLineEdit.Password)

        self.horizontalLayout_2.addWidget(self.loginCred2)

        self.verticalLayout.addWidget(self.widget_4)

        self.widget_5 = QWidget(self.widget_2)
        self.widget_5.setObjectName(u"widget_5")
        self.horizontalLayout_3 = QHBoxLayout(self.widget_5)
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.label = QLabel(self.widget_5)
        self.label.setObjectName(u"label")
        self.label.mousePressEvent = self.forgotPassword

        self.horizontalLayout_3.addWidget(self.label)

        self.horizontalSpacer_3 = QSpacerItem(
            13, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer_3)

        self.switchSignUpButton = QPushButton(self.widget_5)
        self.switchSignUpButton.setObjectName(u"switchSignUpButton")
        self.switchSignUpButton.setCursor(QCursor(Qt.PointingHandCursor))
        icon = QIcon()
        icon.addFile(u"assets/sign-up.png", QSize(), QIcon.Normal, QIcon.Off)
        self.switchSignUpButton.setIcon(icon)
        self.switchSignUpButton.clicked.connect(self.switchUserRegister)
        self.horizontalLayout_3.addWidget(self.switchSignUpButton)

        self.loginButton = QPushButton(self.widget_5)
        self.loginButton.setObjectName(u"loginButton")
        self.loginButton.setCursor(QCursor(Qt.PointingHandCursor))
        icon1 = QIcon()
        icon1.addFile(u"assets/login_icon.png",
                      QSize(), QIcon.Normal, QIcon.Off)
        self.loginButton.setIcon(icon1)
        self.loginButton.clicked.connect(self.getLoginCreds)
        self.horizontalLayout_3.addWidget(self.loginButton)

        self.verticalLayout.addWidget(self.widget_5)
        self.verticalSpacer_2 = QSpacerItem(
            20, 67, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout.addItem(self.verticalSpacer_2)

        self.horizontalLayout_4.addWidget(self.widget_2)

        self.horizontalSpacer_2 = QSpacerItem(
            40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_4.addItem(self.horizontalSpacer_2)

        self.horizontalLayout_16.addWidget(self.userLoginSection)

        self.userRegisterSection = QGroupBox(self.widget)
        self.userRegisterSection.setObjectName(u"userRegisterSection")
        self.userRegisterSection.setEnabled(True)
        self.horizontalLayout_11 = QHBoxLayout(self.userRegisterSection)
        self.horizontalLayout_11.setObjectName(u"horizontalLayout_11")
        self.horizontalSpacer_4 = QSpacerItem(
            40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_11.addItem(self.horizontalSpacer_4)

        self.widget_6 = QWidget(self.userRegisterSection)
        self.widget_6.setObjectName(u"widget_6")
        self.verticalLayout_2 = QVBoxLayout(self.widget_6)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.verticalSpacer_3 = QSpacerItem(
            20, 13, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout_2.addItem(self.verticalSpacer_3)

        self.widget_11 = QWidget(self.widget_6)
        self.widget_11.setObjectName(u"widget_11")
        self.horizontalLayout_9 = QHBoxLayout(self.widget_11)
        self.horizontalLayout_9.setObjectName(u"horizontalLayout_9")
        self.signUpCred0 = QLineEdit(self.widget_11)
        self.signUpCred0.setObjectName(u"signUpCred0")

        self.horizontalLayout_9.addWidget(self.signUpCred0)

        self.verticalLayout_2.addWidget(self.widget_11)

        self.widget_7 = QWidget(self.widget_6)
        self.widget_7.setObjectName(u"widget_7")
        self.horizontalLayout_5 = QHBoxLayout(self.widget_7)
        self.horizontalLayout_5.setObjectName(u"horizontalLayout_5")
        self.signUpCred1 = QLineEdit(self.widget_7)
        self.signUpCred1.setObjectName(u"signUpCred1")

        self.horizontalLayout_5.addWidget(self.signUpCred1)

        self.verticalLayout_2.addWidget(self.widget_7)

        self.widget_8 = QWidget(self.widget_6)
        self.widget_8.setObjectName(u"widget_8")
        self.horizontalLayout_6 = QHBoxLayout(self.widget_8)
        self.horizontalLayout_6.setObjectName(u"horizontalLayout_6")
        self.signUpCred2 = QLineEdit(self.widget_8)
        self.signUpCred2.setObjectName(u"signUpCred2")
        self.signUpCred2.setInputMethodHints(Qt.ImhEmailCharactersOnly)

        self.horizontalLayout_6.addWidget(self.signUpCred2)

        self.verticalLayout_2.addWidget(self.widget_8)

        self.widget_9 = QWidget(self.widget_6)
        self.widget_9.setObjectName(u"widget_9")
        self.horizontalLayout_7 = QHBoxLayout(self.widget_9)
        self.horizontalLayout_7.setObjectName(u"horizontalLayout_7")
        self.signUpCred3 = QLineEdit(self.widget_9)
        self.signUpCred3.setObjectName(u"signUpCred3")
        self.signUpCred3.setEchoMode(QLineEdit.Password)

        self.horizontalLayout_7.addWidget(self.signUpCred3)

        self.verticalLayout_2.addWidget(self.widget_9)

        self.widget_10 = QWidget(self.widget_6)
        self.widget_10.setObjectName(u"widget_10")
        self.horizontalLayout_8 = QHBoxLayout(self.widget_10)
        self.horizontalLayout_8.setObjectName(u"horizontalLayout_8")
        self.signUpCred4 = QLineEdit(self.widget_10)
        self.signUpCred4.setObjectName(u"signUpCred4")
        self.signUpCred4.setContextMenuPolicy(Qt.DefaultContextMenu)
        self.signUpCred4.setAcceptDrops(False)
        self.signUpCred4.setInputMethodHints(
            Qt.ImhHiddenText | Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhSensitiveData)
        self.signUpCred4.setEchoMode(QLineEdit.Password)

        self.horizontalLayout_8.addWidget(self.signUpCred4)

        self.verticalLayout_2.addWidget(self.widget_10)

        self.widget_12 = QWidget(self.widget_6)
        self.widget_12.setObjectName(u"widget_12")
        self.horizontalLayout_10 = QHBoxLayout(self.widget_12)
        self.horizontalLayout_10.setObjectName(u"horizontalLayout_10")
        self.horizontalSpacer_6 = QSpacerItem(
            13, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_10.addItem(self.horizontalSpacer_6)

        self.cancelRegisterButton = QPushButton(self.widget_12)
        self.cancelRegisterButton.setObjectName(u"cancelRegisterButton")
        self.cancelRegisterButton.setCursor(QCursor(Qt.PointingHandCursor))
        icon2 = QIcon()
        icon2.addFile(u"assets/cancel.png", QSize(), QIcon.Normal, QIcon.Off)
        self.cancelRegisterButton.setIcon(icon2)
        self.cancelRegisterButton.clicked.connect(self.switchUserLogin)
        self.horizontalLayout_10.addWidget(self.cancelRegisterButton)

        self.registerButton = QPushButton(self.widget_12)
        self.registerButton.setObjectName(u"registerButton")
        self.registerButton.setCursor(QCursor(Qt.PointingHandCursor))
        icon3 = QIcon()
        icon3.addFile(u"assets/register.png", QSize(), QIcon.Normal, QIcon.Off)
        self.registerButton.setIcon(icon3)
        self.registerButton.clicked.connect(self.getSignUpCreds)
        self.horizontalLayout_10.addWidget(self.registerButton)

        self.verticalLayout_2.addWidget(self.widget_12)

        self.verticalSpacer_4 = QSpacerItem(
            20, 17, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout_2.addItem(self.verticalSpacer_4)

        self.horizontalLayout_11.addWidget(self.widget_6)

        self.horizontalSpacer_5 = QSpacerItem(
            40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_11.addItem(self.horizontalSpacer_5)

        self.horizontalLayout_16.addWidget(self.userRegisterSection)

        self.horizontalLayout_17.addWidget(self.widget)

        self.userRegisterSection.setVisible(False)
        self.retranslateUi(loginSection)

        QMetaObject.connectSlotsByName(loginSection)
    # setupUi

    def retranslateUi(self, loginSection):
        '''
        This is also QtDesigner Generated code to retranslate UI i.e. setting label values, tooltips, placeholder text, etc.
        rtype: None
        '''
        loginSection.setWindowTitle(
            QCoreApplication.translate("loginSection", u"Login", None))
        self.userLoginSection.setTitle(
            QCoreApplication.translate("loginSection", u"User Login", None))
# if QT_CONFIG(tooltip)
        self.loginCred1.setToolTip(QCoreApplication.translate(
            "loginSection", u"Enter Valid Email/Username", None))
#endif // QT_CONFIG(tooltip)
        self.loginCred1.setPlaceholderText(
            QCoreApplication.translate("loginSection", u"Enter Username", None))
# if QT_CONFIG(tooltip)
        self.loginCred2.setToolTip(QCoreApplication.translate(
            "loginSection", u"Enter Password", None))
#endif // QT_CONFIG(tooltip)
        self.loginCred2.setPlaceholderText(
            QCoreApplication.translate("loginSection", u"Enter Password", None))
        self.label.setText(QCoreApplication.translate(
            "loginSection", u"Forgot Password ?", None))
# if QT_CONFIG(tooltip)
        self.switchSignUpButton.setToolTip(
            QCoreApplication.translate("loginSection", u"Register", None))
#endif // QT_CONFIG(tooltip)
        self.switchSignUpButton.setText(
            QCoreApplication.translate("loginSection", u"Sign Up", None))
# if QT_CONFIG(tooltip)
        self.loginButton.setToolTip(
            QCoreApplication.translate("loginSection", u"Login", None))
#endif // QT_CONFIG(tooltip)
        self.loginButton.setText(QCoreApplication.translate(
            "loginSection", u"Login", None))
        self.userRegisterSection.setTitle(
            QCoreApplication.translate("loginSection", u"User Register", None))
# if QT_CONFIG(tooltip)
        self.signUpCred0.setToolTip(QCoreApplication.translate(
            "loginSection", u"Only Alphabets and Spaces are allowed", None))
#endif // QT_CONFIG(tooltip)
        self.signUpCred0.setPlaceholderText(
            QCoreApplication.translate("loginSection", u"Name", None))
# if QT_CONFIG(tooltip)
        self.signUpCred1.setToolTip(QCoreApplication.translate(
            "loginSection", u"<html><head/><body><p>Username should satisfy:</p><p>1. Min Length 3</p><p>2. Contain atleast one alphabet</p><p>3. Contain no spaces</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.signUpCred1.setPlaceholderText(
            QCoreApplication.translate("loginSection", u"Username", None))
# if QT_CONFIG(tooltip)
        self.signUpCred2.setToolTip(QCoreApplication.translate(
            "loginSection", u"Enter Valid Email", None))
#endif // QT_CONFIG(tooltip)
        self.signUpCred2.setPlaceholderText(
            QCoreApplication.translate("loginSection", u"Email", None))
# if QT_CONFIG(tooltip)
        self.signUpCred3.setToolTip(QCoreApplication.translate(
            "loginSection", u"<html><head/><body><p>Password should satisfy:</p><p>1. Minimum 8 Characters</p><p>2. Contain No Spaces</p><p>3. Contain atleast one alphabet, one digit, one uppercase, one lowercase and one special symbol</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.signUpCred3.setPlaceholderText(
            QCoreApplication.translate("loginSection", u"Password", None))
# if QT_CONFIG(tooltip)
        self.signUpCred4.setToolTip(QCoreApplication.translate(
            "loginSection", u"<html><head/><body><p>Should Match Above Password</p></body></html>", None))
#endif // QT_CONFIG(tooltip)
        self.signUpCred4.setPlaceholderText(QCoreApplication.translate(
            "loginSection", u"Confirm Password", None))
# if QT_CONFIG(tooltip)
        self.cancelRegisterButton.setToolTip(
            QCoreApplication.translate("loginSection", u"Cancel Register", None))
#endif // QT_CONFIG(tooltip)
        self.cancelRegisterButton.setText(
            QCoreApplication.translate("loginSection", u"Cancel", None))
# if QT_CONFIG(tooltip)
        self.registerButton.setToolTip(QCoreApplication.translate(
            "loginSection", u"Register Admin", None))
#endif // QT_CONFIG(tooltip)
        self.registerButton.setText(QCoreApplication.translate(
            "loginSection", u"Register", None))
    # retranslateUi
