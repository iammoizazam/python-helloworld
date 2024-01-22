from flask import make_response, send_file,jsonify
from re import search
import re
import os
import json
import firebase_admin
from firebase_admin import credentials, messaging
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from smtplib import SMTP
import pandas as pd
import random
from random import *
from email.message import EmailMessage
from werkzeug.utils import secure_filename
from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher import AES
from base64 import b64encode,b64decode
import json
import string
from flask import Flask
from flask  import render_template, request, url_for, redirect, send_from_directory
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from datetime import datetime,timedelta
from datetime import date
from flask_cors import CORS, cross_origin
from flask_jwt_extended import JWTManager, jwt_required, create_access_token,get_jwt_identity


app = Flask(__name__)
app.CSRF_ENABLED = True
app.config['SECRET_KEY'] = 'convex_application'

# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'convexsql123'
# app.config['MYSQL_DB'] = 'influencer'


app.config['MYSQL_HOST'] = '10.100.50.44'
app.config['MYSQL_USER'] = 'socialpigeon'
app.config['MYSQL_PASSWORD'] = 'SOcial$5432#'
app.config['MYSQL_DB'] = 'influencer'

# app.config['MYSQL_HOST'] = '13.38.89.123'
# app.config['MYSQL_PORT']= 3308
# app.config['MYSQL_USER'] = 'socialpigeon'
# app.config['MYSQL_PASSWORD'] = 'SOcial$5432#'
# app.config['MYSQL_DB'] = 'socialpigeon'



app.config['UPLOAD_FOLDER'] ="userImages"
app.config['MAX_CONTENT_PATH'] = 16 * 1024 * 1024
jwt = JWTManager(app)
cors = CORS(app)
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)

app.config['UPLOADED_PATH'] = os.path.join(app.root_path, 'upload')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
db = SQLAlchemy(app)
mysql = MySQL(app)


bc = Bcrypt(app) # flask-bcrypt
lm = LoginManager() # flask-loginmanager

response= {'status': '', 'message': '','code': '', 'data': ''}

class User():
    @classmethod
    def validate_user(cls,email:str,password:str)->bool:
        if email == 'info@convexinteractive.com' and password == 'convex123':
            return True
        return False

@app.route("/api/auth/TokenGenerate", methods=['POST'])
def token_required():
    try:
        email = request.form.get('email')
        password= request.form.get('password')

        if not email or not password:
            raise ValueError("Email and password are required")

        if not User.validate_user(email, password):
            raise ValueError("Invalid email or password")

        else:
            access_token = create_access_token(identity={"email": email,"password":password},expires_delta=timedelta(hours=1))

            response = {
                'status' : True,
                'messsage' : 'Sucess',
                'code' : 200,
                'data' : {
                "access_token": access_token,
                "token_type" : "bearer",
                "expires_in" : "3300000"
            }
            }
            return make_response(response, 200)

    except Exception as e:
        return jsonify(message=str(e)), 401


@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    response = {
        'status': False,
        'message': 'Fail',
        'code': 401,
        'data': {
            'access_token': 'Token Expired',
            'token_type': 'bearer',
            'expires_in': ''
        }
    }
    encrypted_response = encrypt_data(response)
    return make_response(encrypted_response, 401)





@jwt.invalid_token_loader
def my_invalid_token_callback(jwt_payload):
    response = {
        'status': False,
        'message': 'Fail',
        'code': 401,
        'data': {
            'access_token': 'Token Invalid',
            'token_type': 'bearer',
            'expires_in': ''
        }
    }
    encrypted_response = encrypt_data(response)
    return make_response(encrypted_response, 401)


@jwt.unauthorized_loader
def my_unauthorized_token_callback(jwt_payload):
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    response = {
        'status': False,
        'message': 'Fail',
        'code': 401,
        'data': {
            'access_token': 'Token Unauthorized',
            'token_type': 'bearer',
            'expires_in': ''
        }
    }
    encrypted_response = encrypt_data(response)
    return make_response(encrypted_response, 401)


def sendmail(message,subj,sender_email = "noreply@socialpigeon.io",receiver_email = "noreply@socialpigeon.io"):
    msg = EmailMessage()
    msg.set_content(message)

    msg['Subject'] = subj
    msg['From'] = sender_email
    msg['To'] = receiver_email
    # Send the message via our own SMTP server.
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login(sender_email, "txaovnytpsmmwyoi")
    server.send_message(msg)
    server.quit()

def sendmailCampaign(message,message2,subj):
    msg = MIMEMultipart()
    msg['Subject'] = subj
    msg['From'] = "noreply@socialpigeon.io"

    html = """\
           <html>
             <head></head>
             <body>
             <p>Campaign Information</p>
               {0}
             </body>
           </html>
           """.format(message.to_html(index=False))
    part1 = MIMEText(html, 'html')
    msg.attach(part1)

    html2 = """\
               <html>
                 <head></head>
                 <body>
                 <p>selected Influencer</p>
                   {0}
                 </body>
               </html>
               """.format(message2.to_html(index=False))
    part2 = MIMEText(html2, 'html')
    msg.attach(part2)
    try:
        """Checking for connection errors"""

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.ehlo()  # NOT NECESSARY
        server.starttls()
        server.ehlo()  # NOT NECESSARY
        server.login("noreply@socialpigeon.io", "txaovnytpsmmwyoi")
        server.sendmail(msg['From'], "info@socialpigeon.io", msg.as_string())
        server.close()

    except Exception as e:
        return ("Error for connection: {}".format(e))


    except Exception as error:
        return (error)


def sendPush(title, msg, registration_token, dataObject=None):
    success_result = []
    failure_result = []

    message = messaging.MulticastMessage(
        notification=messaging.Notification(title=title, body=msg),
        data=dataObject,
        tokens=registration_token,
    )
    response = messaging.send_multicast(message)
    for resp, token in zip(response.responses, registration_token):
        if resp.success:
            success_result.append(token)
        else:
            failure_result.append(token)

    return failure_result



def username_Cleaning(medium,username):
    if medium == 'linkedin':
        medium2 = 'LinkedIn'
        medium3 = medium.title()
    else:
        medium2 = medium.title()
    if search("https://"+medium+".com/in/",username):
        res = username.split("https://"+medium+".com/in/", 1)
        username = res[1]
    if search("http://"+medium+".com/in/",username):
        res = username.split("http://"+medium+".com/in/", 1)
        username = res[1]
    if search("https://www."+medium+".com/in/",username):
        res = username.split("https://www."+medium+".com/in/", 1)
        username = res[1]
    if search("http://www."+medium+".com/in/",username):
        res = username.split("http://www."+medium+".com/in/", 1)
        username = res[1]
    if search(medium+".com/in/",username):
        res = username.split(medium+".com/in/", 1)
        username = res[1]
    if search(medium2+".com/in/",username):
        res = username.split(medium2+".com/in/", 1)
        username = res[1]
    if search("https://www."+medium+".com/in/",username):
        res = username.split("https://www."+medium+".com/in/", 1)
        username = res[1]
    if (medium == 'linkedin'):
        if search(medium3+".com/",username):
            res = username.split(medium3+".com/", 1)
            username = res[1]
    if search("Https://www."+medium+".com/in/",username):
        res = username.split("Https://www."+medium+".com/in/", 1)
        username = res[1]
    if search("https://"+medium+".com/",username):
        res = username.split("https://"+medium+".com/", 1)
        username = res[1]
    if search("http://"+medium+".com/",username):
        res = username.split("http://"+medium+".com/", 1)
        username = res[1]
    if search("https://www."+medium+".com/",username):
        res = username.split("https://www."+medium+".com/", 1)
        username = res[1]
    if search("http://www."+medium+".com/",username):
        res = username.split("http://www."+medium+".com/", 1)
        username = res[1]
    if search("https://vt."+medium+".com/",username):
        res = username.split("https://vt."+medium+".com/", 1)
        username = res[1]
    if search(medium+".com/",username):
        res = username.split(medium+".com/", 1)
        username = res[1]
    if search(medium2+".com/",username):
        res =username.split(medium2+".com/", 1)
        username = res[1]
    if search("@", username):
        res = username.split('@', 1)
        username = res[1]
    if (username.find('?')):
        res= username.split('?', 1)
        username = res[0]
    if (username.find('/')):
        res= username.split('/', 1)
        username = res[0]
    return username

def followers_Cleaning(Followers):
    dash_index = Followers.find('-')
    slash_index = Followers.find('/')
    plus_index = Followers.find('+')

    if (int(plus_index) >= 0):
        Followers = Followers[:-1]
    if (int(slash_index) >= 0):
        Followers = Followers[:slash_index]
    if (int(dash_index) >= 0):
        Followers = Followers[:dash_index]

    units = {
        'k': 1000,
        'K': 1000,
        'm': 1000000,
        'M': 1000000
    }
    Followers = Followers.strip()
    Followers = Followers.replace(',', '')
    if " " in Followers:
        Followers = Followers.split(" ")[0]
    for unit, multiplier in units.items():
        if unit in Followers:
            Followers = Followers.split(unit)[0]
            Followers = float(Followers) * multiplier
            break
    try:
        Followers = int(Followers)
    except ValueError:
        Followers = 0
    return Followers


def followers_Appending(Followers):
    Followers = str(Followers)
    if (len(Followers) >= 7):
        Followers = int(Followers) / 1000000
        Followers = str(Followers) + 'M'
    elif (len(Followers) >= 4):
        Followers = int(Followers) / 1000
        Followers = str(Followers) + 'K'
    return Followers


def preloginnfluencer(emailorPhone):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT InfluencerID, FirstName, LastName, Email, PhoneNumber FROM influencers WHERE Email = %s OR PhoneNumber LIKE %s",(emailorPhone,  '%' +emailorPhone))
        influencer_data = cursor.fetchone()
        cursor.close()

        if influencer_data:
            influencer_id, first_name, last_name, email, phone = influencer_data
            cursor = mysql.connection.cursor()
            cursor.execute("select UserId, UserEmail from users where UserEmail = %s OR PhoneNumber LIKE %s", (emailorPhone,'%' +emailorPhone))
            user_data = cursor.fetchone()
            cursor.close()

            if user_data:
                user_id, email = user_data
                cursor = mysql.connection.cursor()
                cursor.execute("select * from logintime where UserId = %s",(str(user_id),))
                result = cursor.fetchone()
                cursor.close()

                if cursor.rowcount > 0 :
                    response = {
                        'status': True,
                        'message': "Success",
                        'code': 200,
                        'data': {
                            "Response": "email or number verified successfully",
                            "isSuccess": True
                        }
                    }
                else:
                    response = {
                        'status': True,
                        'message': 'Success','code': 200,
                        'data': {"Response": "Password has already been sent to " + email + ". If you don't receive it, kindly check your spam",
                                 "isSuccess": True
                                 }
                    }

                return response
            else:
                name = str(first_name) + str(last_name)
                username = first_name
                role = 2
                characters = string.ascii_letters + string.digits + string.punctuation
                password = ''.join(choice(characters) for i in range(8))
                pw_hash = bc.generate_password_hash(password)
                now = datetime.now()
                cursor = mysql.connection.cursor()
                cursor.execute("INSERT INTO users(RoleId, Name, UserName, UserEmail, PhoneNumber, UserPass, IsPasswordUpdated,created_at) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)",
                    (role, name, username, email, phone, pw_hash, 0,now))
                mysql.connection.commit()
                cursor.close()

                subject = "Updated Password"
                message = "Your password for Social Pigeon is " + password
                sendmail(message, subject, receiver_email=email)

                cursor = mysql.connection.cursor()
                cursor.execute("SELECT UserId FROM users ORDER BY UserId DESC LIMIT 1")
                user_id = cursor.fetchone()[0]
                cursor.close()

                cursor = mysql.connection.cursor()
                cursor.execute("update influencers SET UserId=%s where InfluencerID=%s", (user_id, influencer_id))
                mysql.connection.commit()
                cursor.close()

                response = {
                    'status': True,
                    'message': 'Success',
                    'code': 200,
                    'data': {
                        "Response": "password has been sent to " + email + " . if you don\'t recive it kindly check your spam",
                        "isSuccess": True
                    }
                }
                return response
        else:
            response = {
                'status': False,
                'message': "Response Unknown user Please register",
                'code': 400,
                'data': {

                }
            }
            return response
    except Exception as e:
        response = {
            'status': False,
            'message': str(e),
            'code': 400,
            'data': {}
        }
        return response



def insertRecordinfluencer(data):
    cursor = mysql.connection.cursor()
    try:
        check_exist = 0
        influencerID = 0

        if not re.match(r'^\S+@\S+\.\S+$', data['phone']):
            data['phone'] = re.sub(r'^\+?92(0)?|^0', '', data['phone'])
        data['phone'] = data['countrycode'] + data['phone']


        cursor.execute("select * from influencers where Email =%s  OR PhoneNumber LIKE %s",(data['email'], '%' +data['phone']))
        if cursor.fetchone():
            check_exist =check_exist +1
        cursor.execute("select * from brands where Email =%s  OR  Phone LIKE %s",(data['email'],  '%' +data['phone']))
        if cursor.fetchone():
            check_exist =check_exist +1

        if (check_exist == 0) :
            cursor.execute("INSERT INTO influencers (FirstName, LastName, Email,Category,PhoneNumber,Address1,Address2,FollowersAgeRange,RecentBrandSponsorshipWork,AnythingLikeUsToKnow,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(data['Fname'], data['Lname'], data['email'] , data['category'], data['phone'], data['add1'], data['add2'], data['ageRange'], data['BrandSponsor'], data['LikeUsKnow'],datetime.now()))

            influencerID = cursor.lastrowid

            cursor.execute("INSERT INTO influencersocialmedia (InfluencerID, WebsiteLink,YoutubeLink,FacebookLink,InstagramLink,TiktokLink,LinkedInLink,TwitterLink,YouTubeFollowers,FacebookFollowers,InstagramFollowers,TiktokFollowers,LinkedInFollowers,TwitterFollowers,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(influencerID, data['website'], data['youtubelink'], data['facebooklink'] , data['instagramlink'], data['tiktoklink'], data['LinkedInlink'], data['twitterlink'],data['youtubefollowers'], data['facebookfollowers'],  data['instagramfollowers'], data['tiktokfollowers'], data['LinkedInfollowers'],data['twitterfollowers'],datetime.now()))

            socialm = cursor.lastrowid

            print(data)
            youtubecheck = None
            facebookcheck = None
            instagramcheck = None
            tiktokcheck = None
            LinkedIncheck = None
            twittercheck = None

            if data['youtubelink']:
                youtubecheck = '0'

            if data['facebooklink']:
                facebookcheck = '0'

            if data['instagramlink']:
                instagramcheck = '0'

            if data['tiktoklink']:
                tiktokcheck = '0'

            if data['LinkedInlink']:
                LinkedIncheck = '0'

            if data['twitterlink']:
                twittercheck = '0'

            cursor.execute("INSERT INTO paritycheck (InfluSocialMdaID,YoutubeCheck,FacebookCheck,InstagramCheck,TiktokCheck,LinkedinCheck,TwitterCheck,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",(socialm, youtubecheck, facebookcheck, instagramcheck, tiktokcheck, LinkedIncheck, twittercheck,datetime.now()))

            cursor.execute("INSERT INTO influencerscharges (InfluencerID,OnGroundActivityCharges,YoutubeVideoCharge,YoutubeShortCharge,FacebookPostCharge,FacebookVideoCharge,FacebookStoryCharge,InstagramPostCharge,InstagramVideoCharge,InstagramStoryCharge,TiktokCharge,LinkedInCharge,TwitterPostCharge,TwitterVideoCharge,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(influencerID, data['storeraid'], data['youtubevideo'],data['youtubeshorts'], data['facebookpost'], data['facebookvideo'], data['facebookstory'],data['instagrampost'], data['instagramvideo'] ,data['instagramstory'] , data['tiktokcharges'], data['LinkedIncharges'], data['twitterpost'], data['twittervideo'],datetime.now()))
            mysql.connection.commit()
            cursor.close()
            return check_exist,influencerID
        else:
            cursor.close()
        return check_exist ,influencerID

    except Exception as e:
        return str(e)


def getinfluencerprofile(influencerId):
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("select * from influencers  as inf inner join influencersocialmedia as infsm on inf.InfluencerID = infsm.InfluencerID  inner join influencerscharges as infs  on infsm.InfluencerID = infs.InfluencerID inner join paritycheck as pc on  infsm.InfluSocialMdaID = pc.InfluSocialMdaID where inf.InfluencerID = %s", (str(influencerId),))
        desc = cursor.description
        column_names = [col[0] for col in desc]
        res = cursor.fetchone()
        mysql.connection.commit()
        cursor.close()
        if res == None:
            response['status'] = False
            response['message'] = "Response invalid InfluencerId"
            response['code'] = 400
            response['data'] = {}
            return response

        else:
            data = dict(zip(column_names, res))
            if data['Profilepic']:
                data['Profilepic'] = request.url_root + "/api/auth/images/influencerImages/" + data['Profilepic']
            else:
                data['Profilepic'] = request.url_root + "/api/auth/images/influencerImages/defalut_profile.jpg"

            phone = data['PhoneNumber']
            if phone:
                # Remove leading zeros and specified prefixes
                prefixes = ['0', '+920', '920', '+92', '92']
                for prefix in prefixes:
                    if phone.startswith(prefix):
                        phone = phone[len(prefix):]

                # Add the country code as a separate key
                data['countrycode'] = '92'

                # Update the phone number in the result
                data['PhoneNumber'] = phone if phone.startswith('3') else ''

            cursor = mysql.connection.cursor()
            cursor.execute("select  u.UserEmail, u.IsPasswordUpdated from influencers inf inner join users u on u.UserId = inf.UserId where inf.InfluencerID = %s", (str(data['InfluencerID']),))
            result = cursor.fetchone()
            cursor.close()
            if (result):
                data['IsPasswordUpdated'] = result[1]
            else:
                data['IsPasswordUpdated'] = None

            data['Category'] = data['Category'].split(",")
            del data['created_at']
            response['status'] = True
            response['message'] = 'Success'
            response['code'] = 200
            response['data'] = data
            return response
    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] ={}
        return response

def updateRecordinfluencer(data):
    cursor = mysql.connection.cursor()
    try:
        youtubecheck = None
        facebookcheck = None
        instagramcheck = None
        tiktokcheck = None
        LinkedIncheck = None
        twittercheck = None

        if data['youtubelink']:
            youtubecheck = '0'

        if data['facebooklink']:
            facebookcheck = '0'

        if data['instagramlink']:
            instagramcheck = '0'

        if data['tiktoklink']:
            tiktokcheck = '0'

        if data['LinkedInlink']:
            LinkedIncheck = '0'

        if data['twitterlink']:
            twittercheck = '0'

        cursor.execute("update influencers inf inner join influencersocialmedia infsm on inf.InfluencerID = infsm.InfluencerID inner join influencerscharges infch on inf.InfluencerID = infch.InfluencerID inner join paritycheck pc on infsm.InfluSocialMdaID = pc.InfluSocialMdaID SET inf.FirstName = %s ,inf.LastName= %s,inf.Category= %s,inf.Address1= %s,inf.Address2= %s,inf.FollowersAgeRange= %s,inf.RecentBrandSponsorshipWork= %s,inf.AnythingLikeUsToKnow= %s ,infsm.WebsiteLink=%s, infsm.YoutubeLink=%s, infsm.FacebookLink=%s, infsm.InstagramLink=%s, infsm.TiktokLink=%s, infsm.LinkedInLink=%s, infsm.TwitterLink=%s, infsm.YouTubeFollowers=%s, infsm.FacebookFollowers=%s, infsm.InstagramFollowers=%s, infsm.TiktokFollowers=%s, infsm.LinkedInFollowers=%s, infsm.TwitterFollowers=%s, pc.YoutubeCheck =%s,pc.FacebookCheck = %s, pc.InstagramCheck = %s, pc.TiktokCheck = %s, pc.LinkedinCheck = %s, pc.TwitterCheck = %s , infch.OnGroundActivityCharges= %s,infch.YoutubeVideoCharge= %s,infch.YoutubeShortCharge= %s,infch.FacebookPostCharge= %s,infch.FacebookVideoCharge= %s,infch.FacebookStoryCharge= %s,infch.InstagramPostCharge= %s,infch.InstagramVideoCharge= %s,infch.InstagramStoryCharge= %s,infch.TiktokCharge= %s,infch.LinkedInCharge= %s,infch.TwitterPostCharge= %s,infch.TwitterVideoCharge= %s where inf.InfluencerID = %s",(data['Fname'], data['Lname'], data['category'], data['add1'], data['add2'], data['ageRange'], data['BrandSponsor'], data['LikeUsKnow'],data['website'], data['youtubelink'], data['facebooklink'], data['instagramlink'], data['tiktoklink'], data['LinkedInlink'], data['twitterlink'],data['youtubefollowers'], data['facebookfollowers'], data['instagramfollowers'], data['tiktokfollowers'], data['LinkedInfollowers'],data['twitterfollowers'],youtubecheck,facebookcheck, instagramcheck,tiktokcheck, LinkedIncheck,twittercheck,data['storeraid'], data['youtubevideo'],data['youtubeshorts'], data['facebookpost'], data['facebookvideo'], data['facebookstory'],data['instagrampost'], data['instagramvideo'], data['instagramstory'], data['tiktokcharges'], data['LinkedIncharges'], data['twitterpost'], data['twittervideo'],data['influencerId']))
        if (cursor.rowcount > 0) :
            cursor.execute("select ut.devicetoken,ut.userid from usertoken as ut inner join influencers inf on inf.UserId = ut.userid where inf.InfluencerID= %s",(data['influencerId'],) )
            record = cursor.fetchone()
            token = record[0]
            userid = record[1]
            tokens = []
            tokens.append(token)
            noti_head = "profile update"
            noti_content = "Your profile has been updated"
            fail = sendPush(noti_head, noti_content, tokens)
            if (len(fail) <= 0):
                now = datetime.now()
                cursor.execute("INSERT INTO notification (UserId, NotificationContent, Date,Type,created_at) VALUES (%s,%s,%s,%s,%s)",(userid, noti_content, now, noti_head,datetime.now()))
                mysql.connection.commit()
                cursor.close()
        else:
            mysql.connection.commit()
            cursor.close()

        return data['influencerId']

    except Exception as e:
        return str(e)



def generateOTP(otp_size = 4):
    final_otp = ''
    for i in range(otp_size):
        final_otp = final_otp + str(randrange(0,9))
    return final_otp


def encrypt_data(data):
    response={}
    temp ={}
    data = json.dumps(data).encode('utf-8')
    key = b'pplfe775xvye8j81elpo9b14d9c09098'
    iv = b'fpmjlrbhpljoennm'
    cipher = AES.new(key, AES.MODE_CBC,iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size,style='pkcs7'))
    ct = b64encode(ct_bytes).decode('utf-8')
    temp['ciphertext'] = ct
    response['edata'] = temp
    return response


def updateinfluencerpic(influencerId, propic, filename):
    try:
        with mysql.connection.cursor() as cursor:
            cursor.execute("SELECT Email,Profilepic FROM influencers WHERE InfluencerID = %s", (influencerId,))
            result = cursor.fetchone()
            if result:
                email,Profilepic = result
                now = datetime.now()
                formatted_date_time = now.strftime("%Y-%m-%d%H-%M-%S")
                ext = filename.rsplit(".", 1)[-1]
                filename = f"{email}{formatted_date_time}.{ext}"
                cursor.execute("UPDATE influencers SET Profilepic = %s WHERE InfluencerID = %s", (filename, influencerId))
                propic.save(os.path.join("influencerImages", filename))
                file_path = os.path.join("influencerImages", Profilepic)
                os.remove(file_path)
                if (cursor.rowcount > 0):
                    cursor.execute("SELECT ut.devicetoken,ut.userid FROM usertoken as ut INNER JOIN influencers inf ON inf.UserId = ut.userid WHERE inf.InfluencerID = %s", (influencerId,))
                    record = cursor.fetchone()
                    if record:
                        token, userid = record
                        tokens = [token]
                        noti_head = "profile update"
                        noti_content = "Your profile picture has been updated"
                        fail = sendPush(noti_head, noti_content, tokens)
                        if not fail:
                            now = datetime.now()
                            cursor.execute("INSERT INTO notification (UserId, NotificationContent, Date, Type,created_at) VALUES (%s,%s,%s,%s,%s)", (userid, noti_content, now, noti_head,datetime.now()))
                mysql.connection.commit()
                return cursor.rowcount
            return 0
    except Exception as e:
        return str(e)
    finally:
        cursor.close()



def insertcampaignsocialhandle(campaigndetails,filenames,stories):
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM campaigndetail WHERE InfluencerID = %s AND CampaignInfoId = %s AND CampaignExecutionId = %s",(campaigndetails['influencerId'], campaigndetails['campaignInfoId'], campaigndetails['campaignExecutionId']))
        res = cursor.rowcount
        existing_data = cursor.fetchone() if res > 0 else None
        mysql.connection.commit()
        cursor.close()
        if res == 0:
            for social_media, filenames in filenames.items():
                if filenames:
                    filename = ",".join(filenames)
                else:
                    filename = None
                campaigndetails[f"{social_media}Filename"] = filename

            currentDate = datetime.now()
            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO campaigndetail (InfluencerID,CampaignInfoId, CampaignExecutionId, FacebookUrl,InstagramUrl,LinkedinUrl,TiktokUrl,TwitterUrl,YoutubeUrl,Facebookstoryurl,Instagramstoryurl,Linkedinstoryurl,Tiktokstoryurl,Twitterstoryurl,Youtubestoryurl,CreatedAt) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (campaigndetails['influencerId'],  campaigndetails['campaignInfoId'], campaigndetails['campaignExecutionId'], campaigndetails['FacebookUrl'],campaigndetails['InstagramUrl'],campaigndetails['LinkedinUrl'],campaigndetails['TiktokUrl'], campaigndetails['TwitterUrl'],campaigndetails['YoutubeUrl'],campaigndetails.get('facebookFilename', None),campaigndetails.get('instagramFilename', None),campaigndetails.get('linkedinFilename', None),campaigndetails.get('tiktokFilename', None),campaigndetails.get('twitterFilename', None),campaigndetails.get('youtubeFilename', None),currentDate))

            for social_media, platform_stories in stories.items():
                platform_filename = campaigndetails.get(f"{social_media}Filename")
                if platform_filename:
                    platform_filename = platform_filename.split(",")
                    for i, story in enumerate(platform_stories):
                        filepath = os.path.join('campaignSocialHandles', platform_filename[i])
                        story.save(filepath)

            cursor.execute("Update campiagnexecution  SET Status = %s  where CampiagnExecutionId = %s",('waiting for approval', campaigndetails['campaignExecutionId']))
            mysql.connection.commit()
            cursor.close()

        elif int(res) > 0:
            existing_data = dict(zip([col[0] for col in cursor.description], existing_data))
            existing_data['CreatedAt'] = existing_data['CreatedAt'].strftime('%Y-%m-%d %H:%M:%S')
            existing_data['facebookstoryurl'] = existing_data['Facebookstoryurl']
            existing_data['instagramstoryurl'] = existing_data['Instagramstoryurl']
            existing_data['linkedinstoryurl'] = existing_data['Linkedinstoryurl']
            existing_data['tiktokstoryurl'] = existing_data['Tiktokstoryurl']
            existing_data['twitterstoryurl'] = existing_data['Twitterstoryurl']
            existing_data['youtubestoryurl'] = existing_data['Youtubestoryurl']

            del existing_data['Facebookstoryurl']
            del existing_data['Instagramstoryurl']
            del existing_data['Linkedinstoryurl']
            del existing_data['Tiktokstoryurl']
            del existing_data['Twitterstoryurl']
            del existing_data['Youtubestoryurl']

            for social_media, filenames in filenames.items():
                if filenames:
                    filename = ",".join(filenames)
                else:
                    filename = None
                campaigndetails[f"{social_media}Filename"] = filename

                if existing_data[f"{social_media}storyurl"] is not None:
                    if campaigndetails[f"{social_media}Filename"] is not None:
                        campaigndetails[f"{social_media}Filename"] = existing_data[f"{social_media}storyurl"]+ "," + campaigndetails[f"{social_media}Filename"]
                    else:
                        campaigndetails[f"{social_media}Filename"] = existing_data[f"{social_media}storyurl"]

            social_medias = ["Facebook","Instagram","Linkedin","Tiktok","Twitter","Youtube"]

            for social_media in social_medias:
                if existing_data[f"{social_media}Url"] is not None:
                    if campaigndetails[f"{social_media}Url"] is not None:
                        campaigndetails[f"{social_media}Url"] = existing_data[f"{social_media}Url"] +","+ campaigndetails[f"{social_media}Url"]
                    else:
                        campaigndetails[f"{social_media}Url"] = existing_data[f"{social_media}Url"]

            print(campaigndetails)
            currentDate = datetime.now()
            cursor = mysql.connection.cursor()
            cursor.execute("Update campaigndetail SET FacebookUrl=%s,InstagramUrl=%s,LinkedinUrl=%s,TiktokUrl=%s,TwitterUrl=%s,YoutubeUrl=%s,Facebookstoryurl=%s,Instagramstoryurl=%s,Linkedinstoryurl=%s,Tiktokstoryurl=%s,Twitterstoryurl=%s,Youtubestoryurl=%s where InfluencerID = %s AND CampaignInfoId = %s AND CampaignExecutionId = %s",(campaigndetails['FacebookUrl'],campaigndetails['InstagramUrl'],campaigndetails['LinkedinUrl'],campaigndetails['TiktokUrl'], campaigndetails['TwitterUrl'],campaigndetails['YoutubeUrl'],campaigndetails.get('facebookFilename', None),campaigndetails.get('instagramFilename', None),campaigndetails.get('linkedinFilename', None),campaigndetails.get('tiktokFilename', None),campaigndetails.get('twitterFilename', None),campaigndetails.get('youtubeFilename', None),campaigndetails['influencerId'], campaigndetails['campaignInfoId'], campaigndetails['campaignExecutionId']))

            for social_media, platform_stories in stories.items():
                platform_filename = campaigndetails.get(f"{social_media}Filename")
                if platform_filename:
                    platform_filename = platform_filename.split(",")
                    for i, story in enumerate(platform_stories):
                        filepath = os.path.join('campaignSocialHandles', platform_filename[i])
                        story.save(filepath)

            cursor.execute("Update campiagnexecution  SET Status = %s  where CampiagnExecutionId = %s",('waiting for approval', campaigndetails['campaignExecutionId']))
            mysql.connection.commit()
            cursor.close()




        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM campaigndetail WHERE InfluencerID = %s AND CampaignInfoId = %s AND CampaignExecutionId = %s",(campaigndetails['influencerId'], campaigndetails['campaignInfoId'], campaigndetails['campaignExecutionId']))
        res = cursor.fetchone()
        cursor.close()
        data = dict(zip([col[0] for col in cursor.description], res))
        data['CreatedAt'] = data['CreatedAt'].strftime('%Y-%m-%d %H:%M:%S')

        filenames = {"facebook", "instagram", "linkedin", "tiktok", "twitter", "youtube"}
        for social_media in filenames:
            if data[f"{social_media.capitalize()}storyurl"] is not None:
                data[f"{social_media.capitalize()}storyurl"] = [request.url_root + "/api/auth/images/campaignSocialHandles/" + img for img in data[f"{social_media.capitalize()}storyurl"].split(",")]
            else:
                data[f"{social_media.capitalize()}storyurl"] = []

            if data[f"{social_media.capitalize()}Url"] is not None:
                data[f"{social_media.capitalize()}Url"] = data[f"{social_media.capitalize()}Url"].split(",")
            else:
                data[f"{social_media.capitalize()}Url"] = []

        response['status'] = True
        response['message'] = "Your campaign has been successfully submitted for approval. Thank you for your submission. We will review it shortly and contact you if any further information is needed"
        response['code'] = 200
        response['data'] = data
        return response



    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        return response


def updatecampaignsocialhandle(campaigndetails, filenames,stories):
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        cursor = mysql.connection.cursor()
        res = cursor.execute("select * from  campaigndetail where CampaignDetailId =%s",(campaigndetails['CampaignDetailId'],))
        cursor.close()
        if (res > 0):
            for social_media, filenames in filenames.items():
                if filenames:
                    filename = ",".join(filenames)
                else:
                    filename = None
                campaigndetails[f"{social_media}Filename"] = filename

            cursor = mysql.connection.cursor()
            cursor.execute(" update campaigndetail SET FacebookUrl = %s ,InstagramUrl= %s,LinkedinUrl =%s ,TiktokUrl=%s,TwitterUrl=%s,YoutubeUrl=%s,Facebookstoryurl=%s,Instagramstoryurl=%s,Linkedinstoryurl=%s,Tiktokstoryurl=%s,Twitterstoryurl=%s,Youtubestoryurl=%s where CampaignDetailId =%s",(campaigndetails['FacebookUrl'],campaigndetails['InstagramUrl'],campaigndetails['LinkedinUrl'],campaigndetails['TiktokUrl'], campaigndetails['TwitterUrl'],campaigndetails['YoutubeUrl'],campaigndetails.get('facebookFilename', None),campaigndetails.get('instagramFilename', None),campaigndetails.get('linkedinFilename', None),campaigndetails.get('tiktokFilename', None),campaigndetails.get('twitterFilename', None),campaigndetails.get('youtubeFilename', None), campaigndetails['CampaignDetailId']))

            for social_media, platform_stories in stories.items():
                platform_filename = campaigndetails.get(f"{social_media}Filename")
                if platform_filename:
                    platform_filename = platform_filename.split(",")
                    for i, story in enumerate(platform_stories):
                        filepath = os.path.join('campaignSocialHandles', platform_filename[i])
                        story.save(filepath)

            cursor.execute("Update campiagnexecution  SET Status = %s  where CampiagnExecutionId = %s",('waiting for approval', campaigndetails['campaignExecutionId']))
            mysql.connection.commit()
            cursor.close()

            cursor = mysql.connection.cursor()
            cursor.execute( "select * from campaigndetail  where CampaignDetailId = %s",( campaigndetails['CampaignDetailId'],))
            res = cursor.fetchone()
            cursor.close()
            data = dict(zip([col[0] for col in cursor.description], res))
            data['CreatedAt'] = data['CreatedAt'].strftime('%Y-%m-%d %H:%M:%S')

            filenames = {"facebook", "instagram", "linkedin", "tiktok", "twitter", "youtube"}
            for social_media in filenames:
                if data[f"{social_media.capitalize()}storyurl"] is not None:
                    data[f"{social_media.capitalize()}storyurl"] = [
                        request.url_root + "/api/auth/images/campaignSocialHandles/" + img for img in
                        data[f"{social_media.capitalize()}storyurl"].split(",")]
                else:
                    data[f"{social_media.capitalize()}storyurl"] = []

                if data[f"{social_media.capitalize()}Url"] is not None:
                    data[f"{social_media.capitalize()}Url"] = data[f"{social_media.capitalize()}Url"].split(",")
                else:
                    data[f"{social_media.capitalize()}Url"] = []

            response['status'] = True
            response['message'] = "Success"
            response['code'] = 200
            response['data'] = data
            return response
        else:
            response['status'] = False
            response['message'] = "Campaign not exists"
            response['code'] = 400
            response['data'] = {}
            return response

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        return response



@app.route("/api/auth/decrypt",methods=['GET', 'POST'])
def decrypt_data():
    try:
        key = b'pplfe775xvye8j81elpo9b14d9c09098'
        iv =b'fpmjlrbhpljoennm'
        ciphertext = request.form.get('ciphertext')
        ct = b64decode(ciphertext)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size,style='pkcs7')
        return pt
    except (ValueError, KeyError):
        return "Incorrect decryption"



@app.route("/api/auth/influencer/prelogin", methods=['POST'])
@jwt_required()
def prelogininfluencer():
    try:
        if  request.method == "POST":
            emailorPhone = request.form.get('emailorPhone')
            if not re.match(r'^\S+@\S+\.\S+$', emailorPhone):
                emailorPhone = re.sub(r'^\+?92(0)?|^0', '', emailorPhone)

            response = preloginnfluencer(emailorPhone)
            code = response['code']
            return make_response(encrypt_data(response), code)

        else:
            response = {
                'status': False,
                'message': 'Invalid Request',
                'code': 400,
                'data': {}
            }
            return make_response(encrypt_data(response), 400)
    except Exception as e:
        response = {
            'status': False,
            'message': str(e),
            'code': 400,
            'data': {}
        }
        return make_response(encrypt_data(response), 400)


@app.route("/api/auth/influencer/login", methods=['POST'])
@jwt_required()
def logininfluencer():
    try:
        if request.method == "POST":
            emailorPhone = request.form.get('emailorPhone')
            password = request.form.get('password')
            devicetoken = request.form.get('devicetoken')

            if not re.match(r'^\S+@\S+\.\S+$', emailorPhone):
                emailorPhone = re.sub(r'^\+?92(0)?|^0', '', emailorPhone)

            if not devicetoken:
                return make_response(encrypt_data({
                    'status': False,
                    'message': "please provide the device token",
                    'code': 400,
                    'data': {}
                }), 400)

            cursor = mysql.connection.cursor()
            cursor.execute("SELECT Email FROM influencers WHERE Email = %s OR PhoneNumber LIKE %s", (emailorPhone,'%' +emailorPhone))
            if cursor.rowcount == 0:
                cursor.close()
                return make_response(encrypt_data({
                    'status': False,
                    'message': "unknown user please register",
                    'code': 400,
                    'data': {}
                }), 400)

            cursor.execute("SELECT UserId, RoleId, UserPass FROM users WHERE UserEmail = %s OR PhoneNumber LIKE %s",
                           (emailorPhone, '%' +emailorPhone))
            record = cursor.fetchone()
            if not bc.check_password_hash(record[2], password):
                cursor.close()
                return make_response(encrypt_data({
                    'status': False,
                    'message': "Wrong password",
                    'code': 400,
                    'data': {}
                }), 400)

            logininfo = {
                'userid': record[0],
                'roleid': record[1],
            }
            cursor.execute("SELECT Role FROM roles WHERE RoleId = %s", (logininfo['roleid'],))
            logininfo['role'] = cursor.fetchone()[0]
            cursor.execute("SELECT InfluencerID FROM influencers WHERE UserId = %s", (logininfo['userid'],))
            logininfo['influencerid'] = cursor.fetchone()[0]

            cursor.execute("SELECT * FROM usertoken WHERE userid = %s", (logininfo['userid'],))

            if cursor.rowcount == 0:
                cursor.execute("INSERT INTO usertoken (userid, devicetoken,created_at) VALUES (%s, %s, %s)",(logininfo['userid'], devicetoken,datetime.now()))
            else:
                cursor.execute("UPDATE usertoken SET devicetoken = %s WHERE userid = %s",(devicetoken, logininfo['userid']))

            now = datetime.now()
            cursor.execute("INSERT INTO logintime (UserId, LoginTime,created_at) VALUES (%s, %s,%s)", (logininfo['userid'], now,datetime.now()))
            cursor.close()
            if logininfo["role"] in ['Admin', 'Finance', 'Help Desk', 'Brand', 'Influencer']:
                return getprofileinfluencer(logininfo['influencerid'])
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/influencer/logout", methods=['POST'])
@jwt_required()
def logoutinfluencer():
    try:
        if request.method == "POST":
            userid = request.form.get('userid')
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT MAX(LoginID) FROM logintime WHERE UserId = %s", (userid,))
            Loginid = cursor.fetchone()[0]
            cursor.execute("UPDATE logintime SET LogoutTime = CURRENT_TIMESTAMP WHERE LoginID = %s", (Loginid,))
            mysql.connection.commit()
            cursor.close()

            response['status'] = True
            response['message'] = "Logout Successfull"
            response['code'] = 200
            response['data'] = {"Response": "Logout Success", "isSuccess": True}
        else:
            response['status'] = False
            response['message'] = 'Invalid Request'
            response['code'] = 400
            response['data'] = {}


    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}

    finally:
        cursor.close()

    temp = encrypt_data(response)
    return make_response(temp, response['code'])


@app.route("/api/auth/influencer/register", methods=['POST'])
@jwt_required()
def formsubmitinfluencer():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":

            fields = ['Fname', 'Lname', 'email', 'phone', 'add1', 'add2', 'website', 'youtubelink',
                      'youtubefollowers', 'youtubevideo', 'youtubeshorts', 'facebooklink', 'facebookfollowers',
                      'facebookpost', 'facebookvideo', 'facebookstory', 'instagramlink', 'instagramfollowers',
                      'instagrampost', 'instagramvideo', 'instagramstory', 'tiktoklink', 'tiktokfollowers',
                      'tiktokcharges', 'LinkedInlink', 'LinkedInfollowers', 'LinkedIncharges', 'twitterlink',
                      'twitterfollowers', 'twitterpost', 'twittervideo', 'BrandSponsor', 'LikeUsKnow', 'ageRange',
                      'storeraid','countrycode']

            data = {field: request.form.get(field) for field in fields}
            data['category'] = ",".join(request.form.getlist('cat'))
            check_exist,influencerid = insertRecordinfluencer(data)

            if (int(check_exist) == 0):
                return getprofileinfluencer(influencerid)


            elif (int(check_exist) > 0):
                response['status'] = False
                response['message'] = "Response Fail! Email or number already exist"
                response['code'] = 400
                response['data'] = {}
                temp = encrypt_data(response)
                return make_response(temp, 400)
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/influencer/getprofile/<influencerId>",methods=['POST'])
@jwt_required()
def getprofileinfluencer(influencerId):
    if request.method == "POST":
        res = getinfluencerprofile(influencerId)
        code = res['code']
        return make_response(encrypt_data(res), code)


@app.route("/api/auth/influencer/updateprofile",methods=['POST'])
@jwt_required()
def updateprofileinfluencer():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            fields = ['influencerId','Fname', 'Lname', 'email', 'phone', 'add1', 'add2', 'website', 'youtubelink',
                      'youtubefollowers', 'youtubevideo', 'youtubeshorts', 'facebooklink', 'facebookfollowers',
                      'facebookpost', 'facebookvideo', 'facebookstory', 'instagramlink', 'instagramfollowers',
                      'instagrampost', 'instagramvideo', 'instagramstory', 'tiktoklink', 'tiktokfollowers',
                      'tiktokcharges', 'LinkedInlink', 'LinkedInfollowers', 'LinkedIncharges', 'twitterlink',
                      'twitterfollowers', 'twitterpost', 'twittervideo', 'BrandSponsor', 'LikeUsKnow', 'ageRange',
                      'storeraid']

            data = {field: request.form.get(field) for field in fields}
            data['category'] = ",".join(request.form.getlist('cat'))
            influencerid = updateRecordinfluencer(data)
            return getprofileinfluencer(influencerid)
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)

@app.route("/api/auth/influencer/updateProfilePicture",methods=['POST'])
@jwt_required()
def influencerUpdateProfilePicture():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            influencerId=request.form.get('influencerId')
            propic = request.files['propic']
            filename = secure_filename(propic.filename)
            _ =updateinfluencerpic(influencerId,propic,filename)
            return getprofileinfluencer(influencerId)
        else:
            response['status'] = False
            response['message'] = {"Response":"Invalid Influencer"}
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/images/<path:filename>", methods=['GET', 'POST'])
def getimage(filename):
    return send_file(filename, mimetype='image/gif')



@app.route("/api/auth/influencer/getAllCampaign", methods=['POST'])
@jwt_required()
def getInfluencerAllCampaign():

    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == 'POST':
            influencer_id = request.form.get('influencerId')
            InfluencerCat = request.form.get('Category')
            data = {
                "opportunities": 0,
                "totalEarning": 0,
                "ProfilePicture": None
            }

            cursor = mysql.connection.cursor()
            cursor.execute("SELECT COUNT(*) FROM campiagnexecution WHERE Status IN ('Active') AND InfluencerID = %s",(influencer_id,))
            res = cursor.fetchone()
            data['opportunities'] = res[0] if res[0] else 0
            cursor.close()

            cursor = mysql.connection.cursor()
            cursor.execute("""SELECT SUM(Budget) AS total_earning FROM campiagnexecution WHERE status = 'completed' AND InfluencerID = %s """, [influencer_id])
            res = cursor.fetchone()
            data['totalEarning'] = res[0] if res[0] else 0
            cursor.close()

            cursor = mysql.connection.cursor()
            cursor.execute("select Profilepic FROM influencers  WHERE influencerID = %s",(influencer_id,))
            res = cursor.fetchone()
            data['ProfilePicture'] = request.url_root + "/api/auth/images/influencerImages/" + res[0] if res[0] else request.url_root + "/api/auth/images/influencerImages/defalut_profile.jpg"
            cursor.close()

            cursor = mysql.connection.cursor()
            query = "select cinfo.CampaignInfoId,cinfo.BrandId,cinfo.Budget,cinfo.CampaignImage,cinfo.CampaignName,cinfo.SocialMediaPlatforms,cinfo.StartDate,cinfo.EndDate,cinfo.Audience,cinfo.InfluencerCategory,cinfo.CampaignType,cinfo.CampaignDescription,cinfo.CampaignInstructions,cinfo.created_at,brands.Profilepic,brands.BrandName from campaigninfo cinfo inner join brands on cinfo.BrandId = brands.BrandId"
            if InfluencerCat and InfluencerCat != '':
                query += " where InfluencerCategory like %s ORDER BY cinfo.created_at DESC"
                cursor.execute(query, ('%' + InfluencerCat + '%',))
            else:
                query += " ORDER BY cinfo.created_at DESC"
                cursor.execute(query)
            res = cursor.fetchall()
            fg = cursor.rowcount
            cursor.close()

            campaigninfo = []
            if (fg > 0) :
                for rst in res:
                    campaigninfo.append(dict(zip([col[0] for col in cursor.description], rst)))

                TERMS_AND_CONDITION = "These Terms together with the Influencer Campaign Agreement constitute the entire agreement and supersedes any prior agreement of the parties relating to its subject matter."
                PROFILE_PIC_PREFIX = "userImages"
                CAMPAIGN_IMAGE_PREFIX = "campaignImages"

                for dt in campaigninfo:
                    if dt['CampaignImage'] not in (None, ""):
                        dt['CampaignImage'] = [request.url_root + "/api/auth/images/" + CAMPAIGN_IMAGE_PREFIX + "/" + img for img in dt['CampaignImage'].split(",")]
                    else:
                        dt['CampaignImage'] = []

                    if dt['Profilepic'] is not None:
                        dt['Profilepic'] = request.url_root + "/api/auth/images/" + PROFILE_PIC_PREFIX + "/" + dt['Profilepic']
                        dt['BrandLogo'] = dt.pop('Profilepic', None)
                    else:
                        dt['BrandLogo'] = request.url_root + "/api/auth/images/influencerImages/defalut_profile.jpg"

                    dt['created_at'] = (dt['created_at'].strftime("%d/%m/%Y, %H:%M:%S") if dt['created_at'] not in (None, "") else None)

                    for date_field in ['StartDate', 'EndDate']:
                        dt[date_field] = datetime.strptime(dt[date_field], '%Y-%m-%d').strftime("%d/%m/%Y")

                    for field in ['SocialMediaPlatforms', 'InfluencerCategory', 'CampaignType']:
                        dt[field] = dt[field].split(",")

                    dt['TermsAndCondition'] = TERMS_AND_CONDITION

                cursor = mysql.connection.cursor()
                query = "SELECT campaignInfoId, Status FROM campiagnexecution WHERE InfluencerID = %s"
                cursor.execute(query, (influencer_id,))
                execution_res = cursor.fetchall()
                cursor.close()
                execution_dict = {row[0]: row[1] for row in execution_res}
                for dt in campaigninfo:
                    dt['Status'] = execution_dict.get(dt['CampaignInfoId'], 'others')

                status_order = {
                    'active': 0,
                    'waiting for approval': 1,
                    'pending': 2
                }

                # Sort the 'campaigninfo' list
                campaigninfo.sort(key=lambda dt: (status_order.get(dt['Status'], float('inf')), dt['Status']))

                # Move 'others' to the end of the sorted list
                others_index = next((index for index, dt in enumerate(campaigninfo) if dt['Status'] == 'others'), None)
                if others_index is not None:
                    campaigninfo.append(campaigninfo.pop(others_index))

                data['campaigninfo'] = campaigninfo
                response['status'] = True
                response['message'] = 'Success'
                response['code'] = 200
                response['data'] = data
                temp = encrypt_data(response)
                return make_response(temp, 200)
            else:
                data['campaigninfo'] = campaigninfo
                response['status'] = True
                response['message'] = "No Record"
                response['code'] = 200
                response['data'] = data
                temp = encrypt_data(response)
                return make_response(temp, 200)
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/influencer/getMyCampaigns", methods=['POST'])
@jwt_required()
def getinfluencerCampaigns():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        data = []
        if request.method == "POST":
            influencerid = request.form.get('influencerId')
            status = request.form.get('Status')
            cursor = mysql.connection.cursor()
            query ="Select cinf.CampaignInfoId,cinf.BrandId,cinf.Budget,cinf.Status,cinf.CampaignImage,cinf.CampaignName,cinf.SocialMediaPlatforms,cinf.StartDate,cinf.EndDate,cinf.Audience,cinf.InfluencerCategory,cinf.CampaignType,cinf.CampaignDescription,cinf.CampaignInstructions,cinf.created_at,cexe.CampiagnExecutionId,cexe.InfluencerID, cexe.Budget as 'InfluencerBudget',cexe.Status as 'InfluencerStatus',brands.Profilepic,brands.BrandName from campaigninfo  cinf inner join  campiagnexecution cexe on cexe.CampaignInfoId = cinf.CampaignInfoId inner join brands on cinf.BrandId= brands.BrandId where cexe.Status != 'completed' and cexe.InfluencerID= %s"
            if status and status != '':
                status = status.lower()
                query += " and cexe.Status = %s"
                cursor.execute(query, (influencerid,status))
            else:
                cursor.execute(query,(influencerid,))
            res = cursor.fetchall()
            fg = cursor.rowcount
            cursor.close()
            if (fg > 0) :
                for rst in res:
                    data.append(dict(zip([col[0] for col in cursor.description], rst)))

                TERMS_AND_CONDITION = "These Terms together with the Influencer Campaign Agreement constitute the entire agreement and supersedes any prior agreement of the parties relating to its subject matter."
                PROFILE_PIC_PREFIX = "userImages"
                CAMPAIGN_IMAGE_PREFIX = "campaignImages"
                for dt in data:
                    if dt['CampaignImage'] not in (None, ""):
                        dt['CampaignImage'] = [request.url_root + "/api/auth/images/" + CAMPAIGN_IMAGE_PREFIX + "/" + img for img in dt['CampaignImage'].split(",")]
                    else:
                        dt['CampaignImage'] = []

                    if dt['Profilepic'] is not None:
                        dt['Profilepic'] = request.url_root + "/api/auth/images/" + PROFILE_PIC_PREFIX + "/" + dt['Profilepic']
                        dt['BrandLogo'] = dt.pop('Profilepic', None)
                    else:
                        dt['BrandLogo'] = None

                    dt['CamapiagnBudget'] = dt.pop('Budget', None)
                    dt['CampaignStatus'] = dt.pop('Status', None)

                    dt['created_at'] = (dt['created_at'].strftime("%d/%m/%Y, %H:%M:%S") if dt['created_at'] not in (None, "") else None)

                    for date_field in ['StartDate', 'EndDate']:
                        dt[date_field] = datetime.strptime(dt[date_field], '%Y-%m-%d').strftime("%d/%m/%Y")

                    for field in ['SocialMediaPlatforms', 'InfluencerCategory', 'CampaignType']:
                        dt[field] = dt[field].split(",")


                    dt['TermsAndCondition'] = TERMS_AND_CONDITION

                status_order = {
                    'active': 0,
                    'waiting for approval': 1,
                    'pending': 2
                }
                data.sort(key=lambda dt: (status_order.get(dt['InfluencerStatus'], float('inf')), dt['InfluencerStatus']))

                # Move 'others' to the end of the sorted list
                others_index = next((index for index, dt in enumerate(data) if dt['InfluencerStatus'] == 'others'), None)
                if others_index is not None:
                    data.append(data.pop(others_index))

                response['status'] = True
                response['message'] = 'Success'
                response['code'] = 200
                response['data'] = data
                temp = encrypt_data(response)
                return make_response(temp, 200)

            else:
                response['status'] = True
                response['message'] = "No Record"
                response['code'] = 200
                response['data'] = data
                temp = encrypt_data(response)
                return make_response(temp, 200)

        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/influencer/getpastCampaigns", methods=['POST'])
@jwt_required()
def getinfluencerpastCampaigns():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        data = []
        if request.method == "POST":
            influencerid = request.form.get('influencerId')
            cursor = mysql.connection.cursor()
            query = "Select cinf.CampaignInfoId,cinf.BrandId,cinf.Budget,cinf.Status,cinf.CampaignImage,cinf.CampaignName,cinf.SocialMediaPlatforms,cinf.StartDate,cinf.EndDate,cinf.Audience,cinf.InfluencerCategory,cinf.CampaignType,cinf.CampaignDescription,cinf.CampaignInstructions,cinf.created_at,cexe.CampiagnExecutionId,cexe.InfluencerID,cinf.BrandId, cexe.Budget as 'InfluencerBudget' , cexe.Status as 'InfluencerStatus' , brands.BrandName , brands.Profilepic from campaigninfo  cinf inner join  campiagnexecution cexe on cexe.CampaignInfoId = cinf.CampaignInfoId inner join brands on brands.BrandId= cinf.BrandId where cexe.Status = 'completed'  and cexe.InfluencerID = %s"
            cursor.execute(query, (influencerid,))
            res = cursor.fetchall()
            fg = cursor.rowcount
            cursor.close()
            if (fg > 0):
                for rst in res:
                    data.append(dict(zip([col[0] for col in cursor.description], rst)))
                TERMS_AND_CONDITION = "These Terms together with the Influencer Campaign Agreement constitute the entire agreement and supersedes any prior agreement of the parties relating to its subject matter."
                PROFILE_PIC_PREFIX = "userImages"
                CAMPAIGN_IMAGE_PREFIX = "campaignImages"
                for dt in data:
                    if dt['CampaignImage'] not in (None, ""):
                        dt['CampaignImage'] = [request.url_root + "/api/auth/images/" + CAMPAIGN_IMAGE_PREFIX + "/" + img
                                               for img in dt['CampaignImage'].split(",")]
                    else:
                        dt['CampaignImage'] = []

                    if dt['Profilepic'] is not None:
                        dt['Profilepic'] = request.url_root + "/api/auth/images/" + PROFILE_PIC_PREFIX + "/" + dt[
                            'Profilepic']
                        dt['BrandLogo'] = dt.pop('Profilepic', None)
                    else:
                        dt['BrandLogo'] = None

                    dt['CamapiagnBudget'] = dt.pop('Budget', None)
                    dt['CampaignStatus'] = dt.pop('Status', None)

                    dt['created_at'] = (dt['created_at'].strftime("%d/%m/%Y, %H:%M:%S") if dt['created_at'] not in (None, "") else None)

                    for date_field in ['StartDate', 'EndDate']:
                        dt[date_field] = datetime.strptime(dt[date_field], '%Y-%m-%d').strftime("%d/%m/%Y")

                    for field in ['SocialMediaPlatforms', 'InfluencerCategory', 'CampaignType']:
                        dt[field] = dt[field].split(",")

                    dt['TermsAndCondition'] = TERMS_AND_CONDITION

                response['status'] = True
                response['message'] = 'Success'
                response['code'] = 200
                response['data'] = data
                temp = encrypt_data(response)
                return make_response(temp, 200)

            else:
                response['status'] = True
                response['message'] = "No Record"
                response['code'] = 200
                response['data'] = data
                temp = encrypt_data(response)
                return make_response(temp, 200)
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)

@app.route("/api/auth/influencer/insertcampaignsocialhandles", methods=['POST'])
@jwt_required()
def createcampaigndetails():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            campaigndetails = {}

            campaigndetails['influencerId'] = request.form.get('influencerId')
            campaigndetails['campaignInfoId'] = request.form.get('campaignInfoId')
            campaigndetails['campaignExecutionId'] = request.form.get('campaignExecutionId')

            platforms = [("Facebook", "FacebookUrl"), ("Instagram", "InstagramUrl"), ("Linkedin", "LinkedinUrl"),
                         ("Tiktok", "TiktokUrl"), ("Twitter", "TwitterUrl"), ("Youtube", "YoutubeUrl")]

            for platform, url in platforms:
                urls = request.form.get(url)
                if urls:
                    urls = urls[1:-1].split(",")
                    if urls[0] != '':
                        campaigndetails[url] = ",".join(urls)
                    else:
                        campaigndetails[url] = None
                else:
                    campaigndetails[url] = None

            platforms = [("facebook", "FacebookStoryScreenshot"), ("instagram", "InstagramStoryScreenshot"),
                         ("linkedin", "LinkedinStoryScreenshot"), ("tiktok", "TiktokStoryScreenshot"),
                         ("twitter", "TwitterStoryScreenshot"), ("youtube", "YoutubeStoryScreenshot")]

            filenames = {"facebook": [], "instagram": [], "linkedin": [], "tiktok": [], "twitter": [], "youtube": []}
            stories = {"facebook": [], "instagram": [], "linkedin": [], "tiktok": [], "twitter": [], "youtube": []}

            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM campaigndetail WHERE InfluencerID = %s AND CampaignInfoId = %s AND CampaignExecutionId = %s",(campaigndetails['influencerId'], campaigndetails['campaignInfoId'],campaigndetails['campaignExecutionId']))
            res = cursor.rowcount
            existing_data = cursor.fetchone() if res > 0 else None
            if existing_data:
                existing_data = dict(zip([col[0] for col in cursor.description], existing_data))
                existing_data['CreatedAt'] = existing_data['CreatedAt'].strftime('%Y-%m-%d %H:%M:%S')
                existing_data['facebookstoryurl'] = existing_data['Facebookstoryurl']
                existing_data['instagramstoryurl'] = existing_data['Instagramstoryurl']
                existing_data['linkedinstoryurl'] = existing_data['Linkedinstoryurl']
                existing_data['tiktokstoryurl'] = existing_data['Tiktokstoryurl']
                existing_data['twitterstoryurl'] = existing_data['Twitterstoryurl']
                existing_data['youtubestoryurl'] = existing_data['Youtubestoryurl']

                del existing_data['Facebookstoryurl']
                del existing_data['Instagramstoryurl']
                del existing_data['Linkedinstoryurl']
                del existing_data['Tiktokstoryurl']
                del existing_data['Twitterstoryurl']
                del existing_data['Youtubestoryurl']

        for platform, story_name in platforms:
            existing_len = len(existing_data[f"{platform}storyurl"].split(",")) if existing_data else 0
            stories[platform] = request.files.getlist(story_name)
            if len(stories[platform]) > 0 and stories[platform][0]:
                for i, Cimg in enumerate(stories[platform],start=existing_len):
                    filename = secure_filename(Cimg.filename)
                    temp = filename.split(".")
                    filenames[platform].append(platform + "story_" + campaigndetails['influencerId'] + "_" + campaigndetails['campaignInfoId'] + "_" +campaigndetails['campaignExecutionId'] + "_" + str(i) + '.' + temp[-1])
            else:
                filenames[platform] = None

            response = insertcampaignsocialhandle(campaigndetails,filenames,stories)
            code = response['code']
            temp = encrypt_data(response)
            return make_response(temp, code)

        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/influencer/getcampaignsocialhandles", methods=['POST'])
@jwt_required()
def getcampaigndetails():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            campaigndetails = {}
            campaigndetails['CampaignDetailId'] = request.form.get('CampaignDetailId')
            cursor = mysql.connection.cursor()
            cursor.execute("select * from  campaigndetail where CampaignDetailId =%s",( campaigndetails['CampaignDetailId'], ))
            res = cursor.fetchone()
            cursor.close()

            if res == None:
                response['status'] = False
                response['message'] = "Response campaigndetail not exist"
                response['code'] = 400
                response['data'] = {}
                temp = encrypt_data(response)
                return make_response(temp, 400)
            else:
                data = dict(zip([col[0] for col in cursor.description], res))
                data['CreatedAt'] = data['CreatedAt'].strftime('%Y-%m-%d %H:%M:%S')
                filenames = {"facebook", "instagram", "linkedin", "tiktok", "twitter", "youtube"}
                for social_media in filenames:
                    if data[f"{social_media.capitalize()}storyurl"] is not None:
                        data[f"{social_media.capitalize()}storyurl"] = [
                            request.url_root + "/api/auth/images/campaignSocialHandles/" + img for img in
                            data[f"{social_media.capitalize()}storyurl"].split(",")]
                    else:
                        data[f"{social_media.capitalize()}storyurl"] = []

                    if data[f"{social_media.capitalize()}Url"] is not None:
                        data[f"{social_media.capitalize()}Url"] = data[f"{social_media.capitalize()}Url"].split(",")
                    else:
                        data[f"{social_media.capitalize()}Url"] = []

                response['status'] = True
                response['message'] = 'Success'
                response['code'] = 200
                response['data'] = data
                temp = encrypt_data(response)
                return make_response(temp, 200)

        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/influencer/updatecampaignsocialhandles", methods=['POST'])
@jwt_required()
def updatecampaigndetails():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            campaigndetails = {}
            campaigndetails['CampaignDetailId'] = request.form.get('CampaignDetailId')
            cursor = mysql.connection.cursor()
            cursor.execute("select InfluencerID, CampaignInfoId, CampaignExecutionId from campaigndetail where CampaignDetailId ='" +campaigndetails['CampaignDetailId'] + "'")
            rst= cursor.fetchone()
            cursor.close()
            if (cursor.rowcount >0):
                campaigndetails['influencerId'] = str(rst[0])
                campaigndetails['campaignInfoId'] = str(rst[1])
                campaigndetails['campaignExecutionId'] = str(rst[2])
                platforms = [("Facebook", "FacebookUrl"), ("Instagram", "InstagramUrl"), ("Linkedin", "LinkedinUrl"),
                             ("Tiktok", "TiktokUrl"), ("Twitter", "TwitterUrl"), ("Youtube", "YoutubeUrl")]
                for platform, url in platforms:
                    urls = request.form.get(url)
                    if urls:
                        urls = urls[1:-1].split(",")
                        if urls[0] != '':
                            campaigndetails[url] = ",".join(urls)
                        else:
                            campaigndetails[url] = None
                    else:
                        campaigndetails[url] = None

                platforms = [("facebook", "FacebookStoryScreenshot"), ("instagram", "InstagramStoryScreenshot"),
                             ("linkedin", "LinkedinStoryScreenshot"), ("tiktok", "TiktokStoryScreenshot"),
                             ("twitter", "TwitterStoryScreenshot"), ("youtube", "YoutubeStoryScreenshot")]

                filenames = {"facebook": [], "instagram": [], "linkedin": [], "tiktok": [], "twitter": [],
                             "youtube": []}
                stories = {"facebook": [], "instagram": [], "linkedin": [], "tiktok": [], "twitter": [], "youtube": []}

                for platform, story_name in platforms:
                    stories[platform] = request.files.getlist(story_name)
                    if len(stories[platform]) > 0 and stories[platform][0]:
                        for i, Cimg in enumerate(stories[platform]):
                            filename = secure_filename(Cimg.filename)
                            temp = filename.split(".")
                            filenames[platform].append(
                                platform + "story_" + campaigndetails['influencerId'] + "_" + campaigndetails[
                                    'campaignInfoId'] + "_" + campaigndetails['campaignExecutionId'] + "_" + str(
                                    i) + '.' + temp[-1])
                    else:
                        filenames[platform] = None

                response = updatecampaignsocialhandle(campaigndetails, filenames,stories)
                code = response['code']
                temp = encrypt_data(response)
                return make_response(temp, code)
            else:
                response['status'] = False
                response['message'] = "Invalid CampaignDetailId"
                response['code'] = 400
                response['data'] = {}
                temp = encrypt_data(response)
                return make_response(temp, 400)
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)

@app.route("/api/auth/influencer/Wallet",methods=['POST'])
@jwt_required()
def influencerAvailableBalance():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            influencerId = request.form.get('influencerId')
            cursor = mysql.connection.cursor()
            data = {}
            rest = cursor.execute(
                "SELECT SUM(AmountPending) AS available_balance FROM cashflowinfluencer WHERE InfluencerID = %s",
                (influencerId,))
            if rest > 0:
                record = cursor.fetchone()
                available_balance = record[0] or 0
            rest = cursor.execute("SELECT SUM(Budget) AS Pending FROM campiagnexecution WHERE Status = 'active' AND InfluencerID = %s",(influencerId,))
            if rest > 0:
                record = cursor.fetchone()
                pending_cashout = record[0] or 0
            data['PendingCashout'] = pending_cashout
            data['AvailableBalance'] = available_balance
            data['LastUpdatedon'] = str(date.today().strftime("%d/%m/%Y"))
            response['status'] = True
            response['message'] = "Success"
            response['code'] = 200
            response['data'] = data
            temp = encrypt_data(response)
            return make_response(temp, 200)

        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)
    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)
    finally:
        mysql.connection.commit()
        cursor.close()


@app.route("/api/auth/influencer/viewTranscationHistory",methods=['POST'])
@jwt_required()
def viewInfluencerTranscationHistory():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            influencerId=request.form.get('influencerId')
            cursor = mysql.connection.cursor()
            query = "SELECT ci.CampaignName, tf.AmountRelease, tf.ReleaseDate FROM transactioninfluencer tf INNER JOIN cashflowinfluencer cfi ON cfi.CashFlowId = tf.CashFlowId INNER JOIN campaigninfo ci ON ci.CampaignInfoId = cfi.CampaignInfoId WHERE cfi.InfluencerID = %s"
            cursor.execute(query, (influencerId,))
            result = cursor.fetchall()
            cursor.close()
            mysql.connection.commit()
            if not result:
                response['status'] = True
                response['message'] = "No Record"
                response['code'] = 200
                response['data'] = []
                return make_response(encrypt_data(response), 200)
            column_names = [col[0] for col in cursor.description]
            data = [dict(zip(column_names, row)) for row in result]
            for d in data:
                d['ReleaseDate'] = d['ReleaseDate'].strftime("%d/%m/%Y")
                d['Status'] = 'completed'
            response['status'] = True
            response['message'] = "Success"
            response['code'] = 200
            response['data'] = data
            return make_response(encrypt_data(response), 200)
        else:
            response['status'] = False
            response['message'] = "InValid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


#-------------------------------------------------------Forgot password-------------------------------------------------------#

@app.route("/api/auth/forgotpassword", methods=['POST'])
@jwt_required()
def forgotpassword():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            emailorPhone = request.form.get('emailorPhone')

            if not re.match(r'^\S+@\S+\.\S+$', emailorPhone):
                emailorPhone = re.sub(r'^\+?92(0)?|^0', '', emailorPhone)

            cursor = mysql.connection.cursor()
            query = "SELECT * FROM users WHERE UserEmail = %s OR PhoneNumber  LIKE %s"
            res = cursor.execute(query, (emailorPhone, '%'+emailorPhone))
            if res <= 0:
                raise Exception("User not found")

            record = cursor.fetchone()
            userid = int(record[0])  # UserId
            email = record[4]

            cur_otp= generateOTP()

            cursor = mysql.connection.cursor()
            cursor.execute("update users SET otp=%s where UserId=%s", (cur_otp, userid))
            cursor.close()
            mysql.connection.commit()

            subj = "OTP for Social Pigeon"
            message = "your OTP for Social Pigeon is " + cur_otp + "."
            sendmail(message, subj, receiver_email=email)

            response['status'] = True
            response['message'] = "Success"
            response['code'] = 200
            response['data'] = {"Response":"OTP has been sent to " + email + " . if you don\'t recive it kindly check your spam","OTP" : cur_otp,"userid":userid, "isSuccess": True}
            temp = encrypt_data(response)
            return make_response(temp, 200)
        else:
            raise Exception("Invalid Request")

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)

# verifying user otp
@app.route("/api/auth/forgotpasswordotp", methods=['POST'])
@jwt_required()
def forgotpasswordotp():
    response = {'status': False, 'message': '', 'code': 400, 'data': {}}
    try:
        if request.method == "POST":
            user_otp = request.form.get('userOtp')
            userid = request.form.get('userid')
            cursor = mysql.connection.cursor()
            res = cursor.execute("select otp from users where UserId =%s", (userid,))
            if (int(res) > 0):
                generatedotp = cursor.fetchone()[0]
                cursor.close()
            else:
                generatedotp = None
            if (int(user_otp) == int(generatedotp)):

                response['status'] = True
                response['message'] = "Success"
                response['code'] = 200
                response['data'] = {"Response": "OTP Mactched", "isSuccess": True}
                temp = encrypt_data(response)
                return make_response(temp, 200)
            else:
                raise Exception ("OTP Not Matched")
        else:
            raise Exception ("Invalid Request")
    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)

@app.route("/api/auth/updatepassword", methods=['POST'])
@jwt_required()
def updatepassword():
    response = {'status': False, 'message': '', 'code': 400, 'data': {}}
    try:
        if request.method == "POST":
            pas = request.form.get('password')
            emailorPhone= request.form.get('emailorPhone')

            if not re.match(r'^\S+@\S+\.\S+$', emailorPhone):
                emailorPhone = re.sub(r'^\+?92(0)?|^0', '', emailorPhone)


            if not emailorPhone:
                response['status'] = False
                response['message'] = "Fail"
                response['code'] = 400
                response['data'] = {"Response": "please provide the email or phone", "isSuccess": False}
                temp = encrypt_data(response)
                return make_response(temp, 400)

            if not pas:
                response['status'] = False
                response['message'] = "Fail"
                response['code'] = 400
                response['data'] = {"Response": "password cannot be empty", "isSuccess": False}
                temp = encrypt_data(response)
                return make_response(temp, 400)

            pswd = bc.generate_password_hash(pas)
            cursor = mysql.connection.cursor()
            cursor.execute("update users SET UserPass=%s,IsPasswordUpdated=%s where UserEmail=%s or PhoneNumber LIKE %s", (pswd,'1',emailorPhone,'%'+emailorPhone))
            res = cursor.rowcount
            mysql.connection.commit()
            cursor.close()
            if res:
                response['status'] = True
                response['message'] = "Success"
                response['code'] = 200
                response['data'] = {"Response": "Password Updated Successfully", "isSuccess": True}
                temp = encrypt_data(response)
                return make_response(temp, 200)
            else:
                response['status'] = False
                response['message'] = "User not Exist"
                response['code'] = 400
                response['data'] = {}
                temp = encrypt_data(response)
                return make_response(temp, 400)
        else:
            raise Exception ("invalid Request")
    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


#-------------------------------------------------------notification -----------------------------------------------------------------------#

@app.route("/api/auth/notification", methods=['POST'])
@jwt_required()
def notification():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            userid = request.form.get('userid')
            userid = str(userid)
            cursor = mysql.connection.cursor()
            rest=cursor.execute("SELECT NotificationContent, DATE(Date) AS date, TIME_FORMAT(TIME(Date), '%r') AS time FROM notification WHERE Date > NOW() - INTERVAL 7 DAY AND UserId ='"+userid+"'")
            res = cursor.fetchall()
            cursor.close()
            notification = [dict(zip([col[0] for col in cursor.description], rst)) for rst in res]

            for rst in notification:
                rst['date'] = rst['date'].strftime("%d/%m/%Y")

            response['status'] = True
            response['message'] = "Success" if int(rest) > 0 else  "No record Found"
            response['code'] = 200
            response['data'] = notification
            temp = encrypt_data(response)
            return make_response(temp, 200)


    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)
#-----------------------------------------categories, campaign type  and Social Media -----------------------------------------------#

@app.route("/api/auth/getGenericData", methods=['GET', 'POST'])
@jwt_required()
def GenericData():
    try:
        if request.method == 'GET':
            response = {'status': '', 'message': '', 'code': '', 'data': ''}
            genericdata ={}

            cursor = mysql.connection.cursor()
            cursor.execute("select PlatformName from socialmedia")
            genericdata['SocialMediaPlatfrom'] = [rst[0] for rst in cursor.fetchall()]

            cursor.execute("SELECT Categories FROM influencercategory")
            genericdata['CategoriesList'] = [rst[0] for rst in cursor.fetchall()]

            cursor.execute("SELECT CampaignType FROM campaigntype")
            genericdata['CampaignType'] = [rst[0] for rst in cursor.fetchall()]
            mysql.connection.commit()
            cursor.close()
            genericdata['CampaignStatus'] = ['Active', 'Pending', 'Paused','Waiting for Approval', 'Completed']

            response['status'] = True
            response['message'] = "Success"
            response['code'] = 200
            response['data'] = genericdata
            temp = encrypt_data(response)
            return make_response(temp, 200)
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)

#-------------------------------------------------------FeedBack-------------------------------------------------------#

@app.route("/api/auth/FeedBack", methods=['GET', 'POST'])
@jwt_required()
def FeedBack():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == 'POST':
            Userfeedback={}
            Userfeedback['UserId'] = request.form.get('UserId')
            Userfeedback['Feedback'] = request.form.get('Feedback')
            if 'FeedbackDocs' in request.files:
                fdfile = request.files['FeedbackDocs']
            else:
                fdfile = None

            cursor = mysql.connection.cursor()
            cursor.execute("SELECT UserEmail FROM users WHERE UserId=%s", (Userfeedback['UserId'],))
            Userfeedback['UserEmail'] = cursor.fetchone()[0]
            cursor.close()
            filename = Userfeedback['UserEmail'] + '.' + fdfile.filename.rsplit(".", 1)[-1] if fdfile else None

            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO userfeedback (UserId, Feedback, feedbackFile,created_at) VALUES (%s,%s,%s,%s)",(Userfeedback['UserId'], Userfeedback['Feedback'],filename,datetime.now()))
            if filename:
                fdfile.save(os.path.join('FeedbackDocs', filename))
            mysql.connection.commit()
            cursor.close()

            cursor = mysql.connection.cursor()
            cursor.execute("select * from userfeedback where UserFeedbackId = (select max(UserFeedbackId) from userfeedback)")
            data = cursor.fetchone()
            if not data:
                response['status'] = False
                response['message'] = "Feedback doesn't exist"
                response['code'] = 400
                response['data'] = {}
                temp = encrypt_data(response)
                return make_response(temp, 400)

            data = dict(zip([col[0] for col in cursor.description], data))
            feed_docs= None
            if data['feedbackFile']:
                feed_docs = request.url_root + '/api/auth/images/FeedbackDocs/' + data['feedbackFile']
            data['feedbackFile'] = feed_docs
            mysql.connection.commit()
            cursor.close()

            del data['created_at']

            response['status'] = True
            response['message'] = 'Success'
            response['code'] = 200
            response['data'] = data
            temp = encrypt_data(response)
            return make_response(temp, 200)

        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)
#-------------------------------------------------------brands-------------------------------------------------------#

def prelognbrand(emailorPhone):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("select BrandId,BrandName,Email,Phone from  brands where Email= %s OR  Phone  LIKE %s",(emailorPhone , '%' +emailorPhone))
        brand_data = cursor.fetchone()
        cursor.close()
        if brand_data:
            brand_id,brand_name, brand_email,brand_phone = brand_data
            cursor = mysql.connection.cursor()
            cursor.execute("select UserId, UserEmail from users where UserEmail = %s OR  PhoneNumber  LIKE %s ", (emailorPhone , '%' +emailorPhone))
            user_data = cursor.fetchone()
            cursor.close()
            if user_data:
                user_id, email = user_data
                cursor = mysql.connection.cursor()
                cursor.execute("select * from logintime where UserId = %s", (str(user_id),))
                result = cursor.fetchone()
                cursor.close()
                if cursor.rowcount > 0:
                    response = {'status': True,'message': "Success",'code': 200,'data': {"Response": "email or number verified successfully","isSuccess": True}}
                else:
                    response = {'status': True,'message': 'Success', 'code': 200,
                    'data': {"Response": "Password has already been sent to " + email + ". If you don't receive it, kindly check your spam","isSuccess": True}}

                return response
            else:
                role = 3
                characters = string.ascii_letters + string.digits + string.punctuation
                password = ''.join(choice(characters) for i in range(8))
                pw_hash = bc.generate_password_hash(password)
                cursor = mysql.connection.cursor()
                cursor.execute(
                    "INSERT INTO users(RoleId, Name, UserName, UserEmail, PhoneNumber, UserPass, IsPasswordUpdated,created_at) VALUES(%s, %s, %s, %s, %s, %s, %s,%s)",
                    (role, brand_name, brand_name, brand_email, brand_phone, pw_hash, 0,datetime.now()))
                mysql.connection.commit()
                cursor.close()

                subject = "Updated Password"
                message = "Your password for Social Pigeon is " + password
                sendmail(message, subject, receiver_email=brand_email)

                cursor = mysql.connection.cursor()
                cursor.execute("SELECT UserId FROM users ORDER BY UserId DESC LIMIT 1")
                user_id = cursor.fetchone()[0]
                cursor.close()

                cursor = mysql.connection.cursor()
                cursor.execute("update brands SET UserId=%s where BrandId=%s", (user_id, brand_id))
                mysql.connection.commit()
                cursor.close()

                response = {
                    'status': True,
                    'message': 'Success',
                    'code': 200,
                    'data': {
                        "Response": "password has been sent to " + brand_email + " . if you don\'t recive it kindly check your spam",
                        "isSuccess": True
                    }
                }
                return response

        else:
            response = {
                'status': False,
                'message': "Response Unknown user Please register",
                'code': 400,
                'data': {

                }
            }
            return response

    except Exception as e:
        response = {
            'status': False,
            'message': str(e),
            'code': 400,
            'data': {}
        }
        return response


def insertRecordBrand(data):
    cursor = mysql.connection.cursor()
    try:
        check_exist = 0
        brandID = 0
        if not re.match(r'^\S+@\S+\.\S+$', data['phone']):
            data['phone'] = re.sub(r'^\+?92(0)?|^0', '', data['phone'])
        data['phone'] = data['countrycode'] + data['phone']



        cursor.execute("select * from brands where Email = %s  OR  Phone LIKE %s",(data['email'],  '%' +data['phone']))
        if cursor.fetchone():
            check_exist = check_exist + 1
        cursor.execute("select * from influencers where Email = %s  OR PhoneNumber LIKE %s",(data['email'], '%' +data['phone']))
        if cursor.fetchone():
            check_exist = check_exist + 1
        if (check_exist == 0):
            now = datetime.now()
            cursor.execute("INSERT INTO brands (BrandName, Phone, Email,Address1,Address2,created_at) VALUES (%s,%s,%s,%s,%s,%s)",(data['BrandName'], data['phone'], data['email'], data['add1'], data['add2'], now))
            brandID = cursor.lastrowid
            mysql.connection.commit()
            cursor.close()
            return check_exist, brandID
        else:
            cursor.close()
        return check_exist, brandID
    except Exception as e:
        return str(e)


def updateRecordBrand(data):
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("update brands  SET BrandName = %s,Address1= %s,Address2= %s where BrandId = %s",(data['BrandName'],data['add1'],data['add2'],data['BrandId']))
        if (cursor.rowcount >0):
            cursor.execute("select ut.devicetoken,ut.userid from usertoken as ut inner join brands bn on bn.UserId = ut.userid where bn.BrandId=%s",(data['BrandId'],) )

            record = cursor.fetchone()
            token = record[0]
            userid = record[1]
            tokens = []
            tokens.append(token)
            noti_head = "profile update"
            noti_content = "Your profile has been updated"
            fail = sendPush(noti_head, noti_content, tokens)
            if (len(fail) <= 0):
                now = datetime.now()
                cursor.execute("INSERT INTO notification (UserId, NotificationContent, Date,Type,created_at) VALUES (%s,%s,%s,%s,%s)",
                               (userid, noti_content, now, noti_head,datetime.now()))
                mysql.connection.commit()
                cursor.close()
            else:
                mysql.connection.commit()
                cursor.close()
            return data['BrandId']

    except Exception as e:
        return str(e)

def getbrandprofile(brandId):
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("select * from brands where BrandId =%s", (str(brandId),))
        desc = cursor.description
        column_names = [col[0] for col in desc]
        res = cursor.fetchone()
        mysql.connection.commit()
        cursor.close()


        if res == None:
            response['status'] = False
            response['message'] = "Response invalid Brand"
            response['code'] = 400
            response['data'] = {}
            return  response
        else:
            data = dict(zip(column_names, res))
            if data['Profilepic']:
                data['Profilepic'] = request.url_root + "/api/auth/images/userImages/" + data['Profilepic']
            else:
                data['Profilepic'] = request.url_root + "/api/auth/images/influencerImages/defalut_profile.jpg"

            data['created_at'] = (data['created_at'].strftime("%d/%m/%Y, %H:%M:%S") if data['created_at'] not in (None, "") else None)

            phone = data['Phone']
            if phone:
                # Remove leading zeros and specified prefixes
                prefixes = ['0', '+920', '920', '+92', '92']
                for prefix in prefixes:
                    if phone.startswith(prefix):
                        phone = phone[len(prefix):]

                # Add the country code as a separate key
                data['countrycode'] = '92'

                # Update the phone number in the result
                data['Phone'] = phone if phone.startswith('3') else ''


            cursor = mysql.connection.cursor()
            tmp = cursor.execute(
                "select  u.UserEmail, u.IsPasswordUpdated from brands as bnd inner join users u on u.UserId = bnd.UserId where bnd.BrandId  =  %s", (str(brandId),))
            result = cursor.fetchone()
            cursor.close()
            if (result):
                data['IsPasswordUpdated'] = result[1]
            else:
                data['IsPasswordUpdated'] = None

            response['status'] = True
            response['message'] = 'Success'
            response['code'] = 200
            response['data'] = data
            return response
    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        return response


def updatebrandpic(brandId, propic, filename):
    try:
        with mysql.connection.cursor() as cursor:
            cursor.execute("SELECT Email,Profilepic FROM brands WHERE BrandId = %s", (brandId,))
            result = cursor.fetchone()
            if result:
                email,Profilepic = result
                now = datetime.now()
                formatted_date_time = now.strftime("%Y-%m-%d%H-%M-%S")
                ext = filename.rsplit(".", 1)[-1]
                filename = f"{email}{formatted_date_time}.{ext}"
                cursor.execute("update brands  SET Profilepic = %s where BrandId = %s",(filename, brandId))
                propic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], Profilepic)
                os.remove(file_path)
                if (cursor.rowcount > 0):
                    cursor.execute("select ut.devicetoken,ut.userid from usertoken as ut inner join brands bn on bn.UserId = ut.userid where bn.BrandId=%s", (brandId,))
                    record = cursor.fetchone()
                    if record:
                        token, userid = record
                        tokens = [token]
                        noti_head = "profile update"
                        noti_content = "Your profile picture has been updated"
                        fail = sendPush(noti_head, noti_content, tokens)
                        if not fail:
                            now = datetime.now()
                            cursor.execute("INSERT INTO notification (UserId, NotificationContent, Date,Type,created_at) VALUES (%s,%s,%s,%s,%s)",
                                (userid, noti_content, now, noti_head,datetime.now()))
                mysql.connection.commit()
                return cursor.rowcount
            return 0
    except Exception as e:
        return str(e)
    finally:
        cursor.close()


def insertcampaigninfo(campaigninfo,Cimage,filenames):
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("select * from campaigninfo where CampaignName =%s",(campaigninfo['Cname'],))
        res = cursor.rowcount
        mysql.connection.commit()
        cursor.close()
        temp2 = None
        if int(res) == 0:
            now = datetime.now()
            campaigninfo['Cstartdate'] = datetime.strptime(campaigninfo['Cstartdate'], '%d/%m/%Y')
            campaigninfo['Cstartdate'] = campaigninfo['Cstartdate'].strftime('%Y-%m-%d')

            campaigninfo['Cenddate'] = datetime.strptime(campaigninfo['Cenddate'], '%d/%m/%Y')
            campaigninfo['Cenddate'] = campaigninfo['Cenddate'].strftime('%Y-%m-%d')
            cursor = mysql.connection.cursor()
            sql_query = "INSERT INTO campaigninfo (BrandId, Budget, Status, CampaignImage, CampaignName, SocialMediaPlatforms, StartDate, EndDate, Audience, InfluencerCategory, CampaignType, CampaignDescription, CampaignInstructions, created_at)"
            if filenames:
                temp2 = ",".join(filenames)
                for i, Cimg in enumerate(Cimage):
                    Cimg.save(os.path.join('campaignImages', filenames[i]))

            values = (
                campaigninfo['BrandId'], campaigninfo['Cbudget'], campaigninfo['status'], temp2, campaigninfo['Cname'],
                campaigninfo['Csocialmd'], campaigninfo['Cstartdate'], campaigninfo['Cenddate'],
                campaigninfo['CTAudience'], campaigninfo['CinfluencerCategory'], campaigninfo['Ctype'],
                campaigninfo['Cdesc'], campaigninfo['Cinstruct'], now)
            sql_query += " VALUES (" + ",".join(["%s"] * len(values)) + ")"
            cursor.execute(sql_query, values)
            mysql.connection.commit()
            cursor.execute("SELECT LAST_INSERT_ID()")
            CampaignInfoId = cursor.fetchone()[0]
            cursor.close()

            cursor = mysql.connection.cursor()
            query = "SELECT ut.devicetoken, ut.userid FROM usertoken AS ut INNER JOIN brands bn ON bn.UserId = ut.userid WHERE bn.BrandId = %s"
            cursor.execute(query, (campaigninfo['BrandId'],))
            record = cursor.fetchone()
            token, userid = record

            tokens = [token]
            noti_head = "campaign update"
            noti_content = "your campaign has been created Sucessfully"
            fail = sendPush(noti_head, noti_content, tokens)

            if not fail:
                now = datetime.now()
                query = "INSERT INTO notification (UserId, NotificationContent, Date, Type,created_at) VALUES (%s, %s, %s, %s,%s)"
                cursor.execute(query, (userid, noti_content, now, noti_head,datetime.now()))

                query = "UPDATE campaigninfo SET creation_noti = %s, creation_noti_date = %s WHERE CampaignInfoId = %s"
                cursor.execute(query, ('1', now, CampaignInfoId))
                mysql.connection.commit()

            cursor.execute("SELECT CampaignInfoId, BrandId, Budget, Status, CampaignImage, CampaignName, SocialMediaPlatforms, StartDate, EndDate, Audience, InfluencerCategory, CampaignType, CampaignDescription, CampaignInstructions, created_at FROM campaigninfo WHERE CampaignInfoId = %s",(CampaignInfoId,))
            rows = cursor.fetchone()
            cursor.close()

            if not rows:
                response['status'] = False
                response['message'] = "Response campaign not exist"
                response['code'] = 400
                response['data'] = {}
                return response

            data = dict(zip([col[0] for col in cursor.description], rows))
            if data['CampaignImage'] not in (None, ""):
                data['CampaignImage'] = [request.url_root + "/api/auth/images/campaignImages/" + img for img in data['CampaignImage'].split(",")]
            else:
                data['CampaignImage'] = []

            data['created_at'] = ( data['created_at'].strftime("%d/%m/%Y, %H:%M:%S") if data['created_at'] not in (None, "") else None)

            for date_field in ['StartDate', 'EndDate']:
                data[date_field] = datetime.strptime(data[date_field], '%Y-%m-%d').strftime("%d/%m/%Y")

            for field in ['SocialMediaPlatforms', 'InfluencerCategory', 'CampaignType']:
                data[field] = data[field].split(",")

            response['status'] = True
            response['message'] = "Success"
            response['code'] = 200
            response['data'] = data
            return response

        else:
            response['status'] = False
            response['message'] = "campaign already exist"
            response['code'] = 400
            response['data'] = {}
            return response

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        return response



def updatecampagninfo(campaigninfo,Cimage,filenames):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("select * from campaigninfo  where CampaignInfoId =%s", (campaigninfo['CampaignInfoId'],))
        rest = cursor.rowcount
        cursor.close()
        if (int(rest) > 0):
            cursor = mysql.connection.cursor()
            res = cursor.execute("select * from campaigninfo  where CampaignName ='" + campaigninfo['Cname'] +"' and CampaignInfoId <> '" +campaigninfo['CampaignInfoId'] +"'")
            cursor.close()
            temp2 = None
            if (int(res) == 0):
                campaigninfo['Cstartdate'] = datetime.strptime(campaigninfo['Cstartdate'], '%d/%m/%Y')
                campaigninfo['Cstartdate'] = campaigninfo['Cstartdate'].strftime('%Y-%m-%d')

                campaigninfo['Cenddate'] = datetime.strptime(campaigninfo['Cenddate'], '%d/%m/%Y')
                campaigninfo['Cenddate'] = campaigninfo['Cenddate'].strftime('%Y-%m-%d')
                cursor = mysql.connection.cursor()

                sql_query = "update campaigninfo SET  Budget = %s,CampaignImage=%s,CampaignName = %s,SocialMediaPlatforms = %s,StartDate = %s,EndDate = %s,Audience = %s,InfluencerCategory=%s,CampaignType = %s,CampaignDescription = %s,CampaignInstructions = %s where CampaignInfoId = %s"
                if filenames:
                    temp2 = ",".join(filenames)
                    for i, Cimg in enumerate(Cimage):
                        Cimg.save(os.path.join('campaignImages', filenames[i]))

                values = (campaigninfo['Cbudget'],temp2, campaigninfo['Cname'], campaigninfo['Csocialmd'],
                         campaigninfo['Cstartdate'], campaigninfo['Cenddate'], campaigninfo['CTAudience'],
                         campaigninfo['CinfluencerCategory'], campaigninfo['Ctype'], campaigninfo['Cdesc'],
                         campaigninfo['Cinstruct'], campaigninfo['CampaignInfoId'])
                cursor.execute(sql_query, values)
                mysql.connection.commit()
                cursor.close()

                cursor = mysql.connection.cursor()
                cursor.execute("SELECT CampaignInfoId, BrandId, Budget, Status, CampaignImage, CampaignName, SocialMediaPlatforms, StartDate, EndDate, Audience, InfluencerCategory, CampaignType, CampaignDescription, CampaignInstructions, created_at FROM campaigninfo WHERE CampaignInfoId = %s",(campaigninfo['CampaignInfoId'],))
                rows = cursor.fetchone()
                cursor.close()
                if not rows:
                    response['status'] = False
                    response['message'] = "Response campaign not exist"
                    response['code'] = 400
                    response['data'] = {}
                    return response

                data = dict(zip([col[0] for col in cursor.description], rows))
                if data['CampaignImage'] not in (None, ""):
                    data['CampaignImage'] = [request.url_root + "/api/auth/images/campaignImages/" + img for img in
                                             data['CampaignImage'].split(",")]
                else:
                    data['CampaignImage'] = []

                data['created_at'] = (
                    data['created_at'].strftime("%d/%m/%Y, %H:%M:%S") if data['created_at'] not in (None, "") else None)

                for date_field in ['StartDate', 'EndDate']:
                    data[date_field] = datetime.strptime(data[date_field], '%Y-%m-%d').strftime("%d/%m/%Y")

                for field in ['SocialMediaPlatforms', 'InfluencerCategory', 'CampaignType']:
                    data[field] = data[field].split(",")

                response['status'] = True
                response['message'] = "Success"
                response['code'] = 200
                response['data'] = data
                return response

            else:
                response['status'] = False
                response['message'] = "Campaign Name already exist"
                response['code'] = 400
                response['data'] = {}
                return response
        else:
            response['status'] = False
            response['message'] = "Campaign Not Exist"
            response['code'] = 400
            response['data'] = {}
            return response

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        return response



def insertinfluncercampaign(campaignexecution):
    try:
        influencerinfo = []
        campaigninfo = []

        cursor = mysql.connection.cursor()
        sql = "INSERT INTO campiagnexecution (CampaignInfoId, InfluencerID, Budget, Status,created_at) SELECT %s, %s, %s, %s,%s FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM campiagnexecution WHERE CampaignInfoId = %s AND InfluencerID = %s)"
        values = [(campaignexecution['campaignInfoId'], influencerId, campaignexecution['budget'],
                   campaignexecution['status'], datetime.now(),campaignexecution['campaignInfoId'], influencerId)
                  for influencerId in campaignexecution['influencerId']]
        cursor.executemany(sql, values)
        mysql.connection.commit()

        rest = cursor.rowcount
        cursor.close()
        for influencerId  in campaignexecution['influencerId']:
            cursor = mysql.connection.cursor()
            cursor.execute("select InfluencerID,FirstName,LastName,Email,Category,PhoneNumber,Address1 from influencers  where InfluencerID = %s", (influencerId,))
            desc = cursor.description
            res = cursor.fetchone()
            cursor.close()
            column_names = [col[0] for col in desc]
            influencerinfo.append(dict(zip(column_names, res)))

        influencer_df = pd.DataFrame(influencerinfo)

        cursor = mysql.connection.cursor()
        cursor.execute("select CampaignInfoId,BrandId,Budget,Status,CampaignImage,CampaignName,SocialMediaPlatforms,StartDate,EndDate,Audience,InfluencerCategory,CampaignType,CampaignDescription,CampaignInstructions,created_at from campaigninfo where CampaignInfoId =%s", (campaignexecution['campaignInfoId'],))
        desc = cursor.description
        res = cursor.fetchone()
        mysql.connection.commit()
        cursor.close()
        column_names = [col[0] for col in desc]
        campaigninfo.append(dict(zip(column_names, res)))
        for data in campaigninfo:
            data['StartDate'] = datetime.strptime(data['StartDate'], '%Y-%m-%d').strftime("%d/%m/%Y")
            data['EndDate'] = datetime.strptime(data['EndDate'], '%Y-%m-%d').strftime("%d/%m/%Y")
            if not (data['created_at'] is None or data['created_at'] == ""):
                data['created_at'] = data['created_at'].strftime("%d/%m/%Y, %H:%M:%S")
            else:
                data['created_at'] = None

        campaign_df = pd.DataFrame(campaigninfo)
        sendmailCampaign(campaign_df,influencer_df, "Brand Request for Campaign")

        response['status'] = True
        response['message'] = "Campaign for Influencers Created Sucessfully"
        response['code'] = 200
        response['data'] = {}
        return response

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        return response




@app.route("/api/auth/brand/prelogin", methods=['POST'])
@jwt_required()
def preloginbrand():
    try:
        if request.method == "POST":
            emailorPhone = request.form.get('emailorPhone')
            if not re.match(r'^\S+@\S+\.\S+$', emailorPhone):
                emailorPhone = re.sub(r'^\+?92(0)?|^0', '', emailorPhone)

            response = prelognbrand(emailorPhone)
            code = response['code']
            return make_response(encrypt_data(response), code)
        else:
            response = {
                'status': False,
                'message': 'Invalid Request',
                'code': 400,
                'data': {}
            }
            return make_response(encrypt_data(response), 400)
    except Exception as e:
        response = {
            'status': False,
            'message': str(e),
            'code': 400,
            'data': {}
        }
        return make_response(encrypt_data(response), 400)



@app.route("/api/auth/brand/login", methods=['POST'])
@jwt_required()
def loginbrand():
    try:
        if request.method == 'POST':
            emailorPhone = request.form.get('emailorPhone')
            password = request.form.get('password')
            devicetoken = request.form.get('devicetoken')

            if not re.match(r'^\S+@\S+\.\S+$', emailorPhone):
                emailorPhone = re.sub(r'^\+?92(0)?|^0', '', emailorPhone)

            if not devicetoken:
                return make_response(encrypt_data({
                    'status': False,
                    'message': "please provide the device token",
                    'code': 400,
                    'data': {}
                }), 400)

            cursor = mysql.connection.cursor()

            cursor.execute("select Email from brands where Email = %s OR  Phone  LIKE %s", (emailorPhone, '%' + emailorPhone))
            if cursor.rowcount == 0:
                cursor.close()
                return make_response(encrypt_data({
                    'status': False,
                    'message': "unknown user please register",
                    'code': 400,
                    'data': {}
                }), 400)

            cursor.execute("SELECT UserId, RoleId, UserPass FROM users WHERE UserEmail = %s OR PhoneNumber LIKE %s",
                           (emailorPhone, '%'+emailorPhone))
            record = cursor.fetchone()
            if not bc.check_password_hash(record[2], password):
                cursor.close()
                return make_response(encrypt_data({
                    'status': False,
                    'message': "Wrong password",
                    'code': 400,
                    'data': {}
                }), 400)

            logininfo = {
                'userid': record[0],
                'roleid': record[1],
            }
            cursor.execute("SELECT Role FROM roles WHERE RoleId = %s", (logininfo['roleid'],))
            logininfo['role'] = cursor.fetchone()[0]
            cursor.execute("SELECT BrandId FROM brands WHERE UserId = %s", (logininfo['userid'],))
            logininfo['BrandId'] = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM usertoken WHERE userid = %s", (logininfo['userid'],))

            if cursor.rowcount == 0:
                cursor.execute("INSERT INTO usertoken (userid, devicetoken,created_at) VALUES (%s, %s,%s)",
                               (logininfo['userid'], devicetoken,datetime.now()))
            else:
                cursor.execute("UPDATE usertoken SET devicetoken = %s WHERE userid = %s",
                               (devicetoken, logininfo['userid']))

            now = datetime.now()
            cursor.execute("INSERT INTO logintime (UserId, LoginTime,created_at) VALUES (%s, %s,%s)", (logininfo['userid'], now,datetime.now()))
            cursor.close()
            if logininfo["role"] in ['Admin', 'Finance', 'Help Desk', 'Brand', 'Influencer']:
                return getprofilebrand(logininfo['BrandId'])
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/brand/logout", methods=['POST'])
@jwt_required()
def logoutbrand():
    try:
        if request.method == "POST":
            userid = request.form.get('userid')

            cursor = mysql.connection.cursor()
            cursor.execute("select max(LoginID) from logintime where UserId =%s", (userid,))
            Loginid= cursor.fetchone()[0]
            cursor.execute("UPDATE logintime SET LogoutTime = CURRENT_TIMESTAMP WHERE LoginID = %s", (Loginid,))
            mysql.connection.commit()
            cursor.close()


            response['status'] = True
            response['message'] = "Success"
            response['code'] = 200
            response['data'] = {"Response": "Logout Successful", "isSuccess": True}
        else:
            response['status'] = False
            response['message'] = 'Invalid Request'
            response['code'] = 400
            response['data'] = {}

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
    finally:
        cursor.close()

    temp = encrypt_data(response)
    return make_response(temp, response['code'])


@app.route("/api/auth/brand/register", methods=['POST'])
@jwt_required()
def formsubmitbrand():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            fields = ['BrandName', 'email', 'phone', 'add1', 'add2','countrycode']
            data = {field: request.form.get(field) for field in fields}
            check_exist, brandid = insertRecordBrand(data)
            if (int(check_exist) == 0):
                return getprofilebrand(brandid)
            elif (int(check_exist) > 0):
                response['status'] = False
                response['message'] = "Response Fail! Email or number already exist"
                response['code'] = 400
                response['data'] = {}
                temp = encrypt_data(response)
                return make_response(temp, 400)

        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)

@app.route("/api/auth/brand/getprofile/<brandId>",methods=['POST'])
@jwt_required()
def getprofilebrand(brandId):
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    if request.method == "POST":
        res = getbrandprofile(brandId)
        code = res['code']
        return make_response(encrypt_data(res), code)


@app.route("/api/auth/brand/updateprofile",methods=['POST'])
@jwt_required()
def updateprofilebrand():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            fields = ['BrandId', 'BrandName', 'add1', 'add2']
            data = {field: request.form.get(field) for field in fields}
            brandid =updateRecordBrand(data)
            return getprofilebrand(brandid)
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/brand/updateProfilePicture",methods=['POST'])
@jwt_required()
def brandUpdateProfilePicture():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            BrandId=request.form.get('BrandId')
            propic = request.files['propic']
            filename = secure_filename(propic.filename)
            _ =updatebrandpic(BrandId,propic,filename)
            return getprofilebrand(BrandId)
        else:
            response['status'] = False
            response['message'] = {"Response":"Invalid Brand"}
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/brand/getMyOpportunities", methods=['POST'])
@jwt_required()
def getbrandOpportunities():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            BrandId = request.form.get('BrandId')
            status = request.form.get('Status')
            data={
            "totalSpending" : 0,
            "activeCampaigns" : 0,
            "Profilepic" : None
            }
            cursor = mysql.connection.cursor()
            cursor.execute("select sum(Budget) as 'Total Spending' from campaigninfo where Status = 'completed' and BrandId=%s", (BrandId,))
            res = cursor.fetchone()
            data['totalSpending'] = res[0] if res[0] else 0
            cursor.close()

            cursor = mysql.connection.cursor()
            cursor.execute("select count(*) as active_campaigns from campaigninfo where  status = 'active'  and BrandId =%s", (BrandId,))
            res = cursor.fetchone()
            data['activeCampaigns'] = res[0] if res[0] else 0
            cursor.close()

            cursor = mysql.connection.cursor()
            cursor.execute("select Profilepic from brands where BrandId = %s",(BrandId,))
            res = cursor.fetchone()
            data['Profilepic'] = request.url_root + "/api/auth/images/userImages/" +res[0] if res[0] else  request.url_root + "/api/auth/images/influencerImages/defalut_profile.jpg"
            cursor.close()

            query = "SELECT cinf.CampaignInfoId,cinf.BrandId,cinf.Budget,cinf.Status,cinf.CampaignImage,cinf.CampaignName,cinf.SocialMediaPlatforms,cinf.StartDate,cinf.EndDate,cinf.Audience,cinf.InfluencerCategory AS BrandCategory,cinf.CampaignType,cinf.CampaignDescription,cinf.CampaignInstructions,cinf.created_at,brands.Profilepic,brands.BrandName, GROUP_CONCAT(CONCAT(inf.FirstName, ' ', inf.LastName) SEPARATOR ',') AS InfluencerName FROM campaigninfo cinf INNER JOIN brands ON brands.BrandId = cinf.BrandId LEFT JOIN campiagnexecution ce ON ce.CampaignInfoId = cinf.CampaignInfoId LEFT JOIN influencers inf ON inf.InfluencerID = ce.InfluencerID WHERE cinf.BrandId = %s"
            params = [BrandId]
            if status:
                status = status.lower()
                query += " AND cinf.Status = %s"
                params.append(status)
            query += " GROUP BY cinf.CampaignInfoId ORDER BY cinf.created_at DESC"

            with mysql.connection.cursor() as cursor:
                cursor.execute(query, params)
                res = cursor.fetchall()
                fg = cursor.rowcount
            if fg > 0:
                campaigninfo = []
                for rst in res:
                    dt = dict(zip([col[0] for col in cursor.description], rst))

                    dt['CampaignImage'] = [request.url_root + "/api/auth/images/campaignImages/" + img for img in
                                           dt['CampaignImage'].split(",")] if dt['CampaignImage'] else []
                    dt['BrandLogo'] = None
                    if dt['Profilepic']:
                        dt['BrandLogo'] = request.url_root + "/api/auth/images/userImages/" + dt['Profilepic']
                    del dt['Profilepic']

                    dt['created_at'] = dt['created_at'].strftime("%d/%m/%Y, %H:%M:%S") if dt['created_at'] else None

                    for date_field in ['StartDate', 'EndDate']:
                        dt[date_field] = datetime.strptime(dt[date_field], '%Y-%m-%d').strftime("%d/%m/%Y")

                    for field in ['SocialMediaPlatforms', 'BrandCategory', 'CampaignType']:
                        dt[field] = dt[field].split(",")

                    dt['TermsAndCondition'] = "These Terms together with the Influencer Campaign Agreement constitute the entire agreement and supersedes any prior agreement of the parties relating to its subject matter."

                    campaigninfo.append(dt)

                data['campaigninfo'] = campaigninfo

                response = {'status': True, 'message': 'Success', 'code': 200, 'data': data}
            else:
                data['campaigninfo'] = []
                response = {'status': True, 'message': 'No Record', 'code': 200, 'data': data}

            temp = encrypt_data(response)
            return make_response(temp, 200)

        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/brand/getMyOpportunitiesInfluencers", methods=['POST'])
@jwt_required()
def getMyOpportunitiesInfluencers():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            campaignInfoId = request.form.get('campaignInfoId')
            Influencerinfo = []
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT concat(FirstName,' ',Lastname) AS InfluencerName,Category,profilepic,Status FROM campiagnexecution cexe INNER JOIN influencers inf ON inf.InfluencerID = cexe.InfluencerID WHERE campaignInfoId = %s", (campaignInfoId,))
            res = cursor.fetchall()
            fg = cursor.rowcount
            if fg > 0:
                for rst in res:
                    dt = dict(zip([col[0] for col in cursor.description], rst))
                    if dt['profilepic']:
                        dt['profilepic'] = request.url_root + "/api/auth/images/influencerImages/" + dt['profilepic']
                    else:
                        dt['profilepic'] = request.url_root + "/api/auth/images/influencerImages/defalut_profile.jpg"
                    Influencerinfo.append(dt)
                response = {'status': True, 'message': 'Success', 'code': 200, 'data': Influencerinfo}
            else:
                response = {'status': True, 'message': 'No Record', 'code': 200, 'data': Influencerinfo}

            cursor.close()
            temp = encrypt_data(response)
            return make_response(temp, 200)

        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)
    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)

@app.route("/api/auth/brand/createcampaign",methods=['POST'])
@jwt_required()
def createcampaign():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            filenames = []
            fields = ['BrandId', 'Cname', 'Cstartdate', 'Cenddate', 'Cbudget', 'CTAudience', 'Cdesc', 'Cinstruct']
            fields_list = ['Csocialmd','CinfluencerCategory','Ctype']
            campaigninfo = {field: request.form.get(field) for field in fields}
            campaigninfo.update({field: ",".join(request.form.getlist(field)) for field in fields_list})
            campaigninfo['status'] = "pending"
            Cimage = request.files.getlist('Cimage')
            if len(Cimage) > 0 and  Cimage[0]:
                for i, Cimg in enumerate(Cimage):
                    filename = secure_filename(Cimg.filename)
                    temp = filename.split(".")
                    filenames.append(campaigninfo['Cname'].replace(' ', '') +str(i) +'.' + temp[-1])
            else:
                Cimage = ''
                filenames = None

            response= insertcampaigninfo(campaigninfo,Cimage,filenames)
            code = response['code']
            temp = encrypt_data(response)
            return make_response(temp, code)
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/brand/getcampaign",methods=['POST'])
@jwt_required()
def getcampaign():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            campaigninfo= {}
            campaigninfo['CampaignInfoId']  = request.form.get('CampaignInfoId')

            cursor = mysql.connection.cursor()
            cursor.execute("select CampaignInfoId,BrandId,Budget,Status,CampaignImage,CampaignName,SocialMediaPlatforms,StartDate,EndDate,Audience,InfluencerCategory,CampaignType,CampaignDescription,CampaignInstructions,created_at from campaigninfo where CampaignInfoId = %s",(campaigninfo['CampaignInfoId'],))
            rows = cursor.fetchone()
            cursor.close()

            if not rows:
                response['status'] = False
                response['message'] = "Response campaign not exist"
                response['code'] = 400
                response['data'] = {}
                temp = encrypt_data(response)
                return make_response(temp, 400)

            data = dict(zip([col[0] for col in cursor.description], rows))
            if data['CampaignImage'] not in (None, ""):
                data['CampaignImage'] = [request.url_root + "/api/auth/images/campaignImages/" + img for img in
                                         data['CampaignImage'].split(",")]
            else:
                data['CampaignImage'] = []

            data['created_at'] = (data['created_at'].strftime("%d/%m/%Y, %H:%M:%S") if data['created_at'] not in (None, "") else None)

            for date_field in ['StartDate', 'EndDate']:
                data[date_field] = datetime.strptime(data[date_field], '%Y-%m-%d').strftime("%d/%m/%Y")

            for field in ['SocialMediaPlatforms', 'InfluencerCategory', 'CampaignType']:
                data[field] = data[field].split(",")

            response['status'] = True
            response['message'] = "Success"
            response['code'] = 200
            response['data'] = data
            temp = encrypt_data(response)
            return make_response(temp, 200)

        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = []
            temp = encrypt_data(response)
            return make_response(temp, 400)


    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/brand/updatecampaign",methods=['POST'])
@jwt_required()
def updatecampaign():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            filenames = []
            fields = ['CampaignInfoId', 'Cname', 'Cstartdate', 'Cenddate', 'Cbudget', 'CTAudience', 'Cdesc', 'Cinstruct']
            fields_list = ['Csocialmd', 'CinfluencerCategory', 'Ctype']
            campaigninfo = {field: request.form.get(field) for field in fields}
            campaigninfo.update({field: ",".join(request.form.getlist(field)) for field in fields_list})

            Cimage = request.files.getlist('Cimage')
            if len(Cimage) > 0 and Cimage[0]:
                for i, Cimg in enumerate(Cimage):
                    filename = secure_filename(Cimg.filename)
                    temp = filename.split(".")
                    filenames.append(campaigninfo['Cname'].replace(' ', '') + str(i) + '.' + temp[-1])
            else:
                Cimage = ''
                filenames = None

            response= updatecampagninfo(campaigninfo,Cimage,filenames)
            code = response['code']
            temp = encrypt_data(response)
            return make_response(temp, code)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/brand/createinfluencercampaign",methods=['POST'])
@jwt_required()
def createinfluencercampaign():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            campaignexecution = {}

            campaignexecution['campaignInfoId'] = request.form.get('campaignInfoId')
            campaignexecution['influencerId']  = request.form.get('influencerId')

            campaignexecution['budget']  ='0'
            campaignexecution['status']  = 'pending'

            campaignexecution['influencerId'] = campaignexecution['influencerId'].split(sep=",", maxsplit=-1)
            response = insertinfluncercampaign(campaignexecution)
            code = response['code']
            temp = encrypt_data(response)
            return make_response(temp, code)
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] =str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)



@app.route("/api/auth/brand/getAIinfluencerSelection",methods=['POST'])
@jwt_required()
def getAIinfluencers():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            campaigninfluencers = {
                'CinfluencerCategory': request.form.get('CinfluencerCategory').split(","),
                'Csocialmd': request.form.get('Csocialmd').split(","),
                'campaignBudget': request.form.get('campaignBudget')
            }

            catquery = ' OR '.join(f"inf.Category LIKE '%{cat}%'" for cat in campaigninfluencers['CinfluencerCategory'])
            socialquery = ' AND '.join(
                f"ism.{sm.lower().capitalize()}Link <> ''" for sm in campaigninfluencers['Csocialmd'])

            query = f"SELECT inf.InfluencerID,inf.FirstName,inf.LastName,ism.YouTubeFollowers,ism.FacebookFollowers,ism.InstagramFollowers,ism.TiktokFollowers,ism.LinkedInFollowers,ism.TwitterFollowers,ism.YoutubeLink,ism.FacebookLink,ism.InstagramLink,ism.TiktokLink,ism.LinkedInLink,ism.TwitterLink,inc.FacebookPostCharge,inc.FacebookVideoCharge,inc.FacebookStoryCharge,inc.YoutubeVideoCharge,inc.YoutubeShortCharge,inc.InstagramPostCharge,inc.InstagramVideoCharge,inc.InstagramStoryCharge,inc.TiktokCharge,inc.LinkedInCharge,inc.TwitterPostCharge,inc.TwitterVideoCharge,t.ProfilePicUrl AS twitterPic,tk.AvatarImageUrl AS tiktokPic,ins.ProfilePicUrl AS instagramPic,inf.Profilepic AS Profilepic FROM influencers inf INNER JOIN influencersocialmedia ism ON inf.InfluencerID = ism.InfluencerID INNER JOIN influencerscharges inc ON inf.InfluencerID = inc.InfluencerID LEFT JOIN twitter AS t ON ism.InfluSocialMdaID = t.InfluSocialMdaID LEFT JOIN tiktok AS tk ON ism.InfluSocialMdaID = tk.InfluSocialMdaID LEFT JOIN instagram AS ins ON ism.InfluSocialMdaID = ins.InfluSocialMdaID WHERE ({catquery}) AND {socialquery}"

            cursor = mysql.connection.cursor()
            cursor.execute(query)
            res = cursor.fetchall()
            ct= cursor.rowcount
            column_names = [col[0] for col in cursor.description]
            data = [dict(zip(column_names, row)) for row in res]
            cursor.close()
            if (int(ct) > 0):
                for dt in data:
                    if dt['Profilepic']:
                        dt['Profilepic'] = request.url_root + "/api/auth/images/influencerImages/" + dt['Profilepic']
                    else:
                        dt['Profilepic'] = request.url_root + "/api/auth/images/influencerImages/defalut_profile.jpg"
                    check=0
                    followers_total = 0
                    platform_urls = {
                        'Youtube': 'https://www.youtube.com/c/',
                        'Facebook': 'https://www.facebook.com/',
                        'Instagram': 'https://www.instagram.com/',
                        'Tiktok': 'https://www.tiktok.com/@',
                        'LinkedIn': 'https://www.linkedin.com/in/',
                        'Twitter': 'https://www.twitter.com/'
                    }

                    for key, value in dt.items():
                        if key.endswith('Link') and value:
                            platform = key[:-4]
                            lnk = username_Cleaning(platform.lower(), value)
                            final = platform_urls[platform] + lnk
                            dt[key] = final

                    pic_keys = ['twitterPic', 'tiktokPic', 'instagramPic']
                    for key in pic_keys:
                        if not dt.get(key):
                            dt[key] = ""

                    platforms = ['YouTube', 'Facebook', 'Instagram', 'Tiktok', 'LinkedIn', 'Twitter']
                    for platform in platforms:
                        followers = dt.get(platform + 'Followers', '')
                        if followers:
                            followers = followers_Cleaning(followers)
                        else:
                            followers = 0
                            check += 1
                        dt[platform + 'Followers'] = followers
                        followers_total += followers

                    dt['FollowersAverage'] = int(followers_total / (len(platforms) - check))
                    del_keys = [platform + 'Followers' for platform in platforms]
                    for key in del_keys:
                        del dt[key]
                    dt['FollowersAverage'] = followers_Appending(dt['FollowersAverage'])
                    platforms = ['FacebookPost', 'FacebookVideo', 'FacebookStory', 'YoutubeVideo', 'YoutubeShort',
                                 'InstagramPost', 'InstagramVideo', 'InstagramStory', 'Tiktok', 'LinkedIn',
                                 'TwitterPost', 'TwitterVideo']
                    for platform in platforms:
                        charge_key = platform + 'Charge'
                        if charge_key in dt:
                            dt[charge_key] = followers_Cleaning(dt[charge_key])
                        else:
                            dt[charge_key] = 0

                    dt['isChecked'] = False

                budget = int(campaigninfluencers['campaignBudget'])
                budget_influencer = int(budget * 0.3)
                shuffle(data)

                for influencer in data:
                    charges = [int(influencer[key]) for key in influencer.keys() if key.endswith("Charge")]
                    max_charge = max(charges)
                    if budget_influencer + max_charge <= budget:
                        influencer['isChecked'] = True
                        budget_influencer += max_charge

                for influencer in data:
                    influencer_copy = influencer.copy()  # create a copy of the dictionary
                    for key in influencer_copy.keys():
                        if key.endswith("Charge"):
                            del influencer[key]

                data = sorted(data, key=lambda i: i['isChecked'], reverse=True)

                response['status'] = True
                response['message'] = 'Success'
                response['code'] = 200
                response['data'] = data
                temp = encrypt_data(response)
                return make_response(temp, 200)
            else:
                    response['status'] = True
                    response['message'] = "No Record Found"
                    response['code'] = 200
                    response['data'] = []
                    temp = encrypt_data(response)
                    return make_response(temp, 200)
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)


@app.route("/api/auth/brand/getManualInfluencerSelection",methods=['POST'])
@jwt_required()
def getManualInfluencers():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            campaigninfluencers = {
                'CinfluencerCategory': request.form.get('CinfluencerCategory').split(","),
                'Csocialmd': request.form.get('Csocialmd').split(",")}

            catquery = ' OR '.join(f"inf.Category LIKE '%{cat}%'" for cat in campaigninfluencers['CinfluencerCategory'])
            socialquery = ' AND '.join(f"ism.{sm.lower().capitalize()}Link <> ''" for sm in campaigninfluencers['Csocialmd'])
            query = f"SELECT inf.InfluencerID,inf.FirstName,inf.LastName,ism.YouTubeFollowers,ism.FacebookFollowers,ism.InstagramFollowers,ism.TiktokFollowers,ism.LinkedInFollowers,ism.TwitterFollowers,ism.YoutubeLink,ism.FacebookLink,ism.InstagramLink,ism.TiktokLink,ism.LinkedInLink,ism.TwitterLink,inc.FacebookPostCharge,inc.FacebookVideoCharge,inc.FacebookStoryCharge,inc.YoutubeVideoCharge,inc.YoutubeShortCharge,inc.InstagramPostCharge,inc.InstagramVideoCharge,inc.InstagramStoryCharge,inc.TiktokCharge,inc.LinkedInCharge,inc.TwitterPostCharge,inc.TwitterVideoCharge,t.ProfilePicUrl AS twitterPic,tk.AvatarImageUrl AS tiktokPic,ins.ProfilePicUrl AS instagramPic,inf.Profilepic AS Profilepic FROM influencers inf INNER JOIN influencersocialmedia ism ON inf.InfluencerID = ism.InfluencerID INNER JOIN influencerscharges inc ON inf.InfluencerID = inc.InfluencerID LEFT JOIN twitter AS t ON ism.InfluSocialMdaID = t.InfluSocialMdaID LEFT JOIN tiktok AS tk ON ism.InfluSocialMdaID = tk.InfluSocialMdaID LEFT JOIN instagram AS ins ON ism.InfluSocialMdaID = ins.InfluSocialMdaID WHERE ({catquery}) AND {socialquery}"

            cursor = mysql.connection.cursor()
            cursor.execute(query)
            res = cursor.fetchall()
            ct = cursor.rowcount
            column_names = [col[0] for col in cursor.description]
            data = [dict(zip(column_names, row)) for row in res]
            cursor.close()

            if (int(ct) > 0):
                for dt in data:
                    if dt['Profilepic']:
                        dt['Profilepic'] = request.url_root + "/api/auth/images/influencerImages/" + dt['Profilepic']
                    else:
                        dt['Profilepic'] = request.url_root + "/api/auth/images/influencerImages/defalut_profile.jpg"
                    check=0
                    followers_total = 0
                    platform_urls = {
                        'Youtube': 'https://www.youtube.com/c/',
                        'Facebook': 'https://www.facebook.com/',
                        'Instagram': 'https://www.instagram.com/',
                        'Tiktok': 'https://www.tiktok.com/@',
                        'LinkedIn': 'https://www.linkedin.com/in/',
                        'Twitter': 'https://www.twitter.com/'
                    }
                    for key, value in dt.items():
                        if key.endswith('Link') and value:
                            platform = key[:-4]
                            lnk = username_Cleaning(platform.lower(), value)
                            final = platform_urls[platform] + lnk
                            dt[key] = final

                    pic_keys = ['twitterPic', 'tiktokPic', 'instagramPic']
                    for key in pic_keys:
                        if not dt.get(key):
                            dt[key] = ""

                    platforms = ['YouTube', 'Facebook', 'Instagram', 'Tiktok', 'LinkedIn', 'Twitter']
                    for platform in platforms:
                        followers = dt.get(platform + 'Followers', '')
                        if followers:
                            followers = followers_Cleaning(followers)
                        else:
                            followers = 0
                            check += 1
                        dt[platform + 'Followers'] = followers
                        followers_total += followers

                    dt['FollowersAverage'] = int(followers_total / (len(platforms) - check))
                    del_keys = [platform + 'Followers' for platform in platforms]
                    for key in del_keys:
                        del dt[key]
                    dt['FollowersAverage'] = followers_Appending(dt['FollowersAverage'])


                response['status'] = True
                response['message'] = 'Success'
                response['code'] = 200
                response['data'] = data
                temp = encrypt_data(response)
                return make_response(temp, 200)

            else:
                response['status'] = True
                response['message'] = "No Record Found"
                response['code'] = 200
                response['data'] = data
                temp = encrypt_data(response)
                return make_response(temp, 200)
        else:
            response['status'] = False
            response['message'] = "Invalid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)

@app.route("/api/auth/brand/getcampaigninsights",methods=['POST'])
@jwt_required()
def getcampaigninsights():
    try:
        if request.method != "POST":
            response = {'status': False, 'message': 'Invalid Social media request', 'data': {}}
            return make_response(encrypt_data(response), 400)

        CampaignInfoId = request.form.get('CampaignInfoId')
        with mysql.connection.cursor() as cursor:
            cursor.execute("SELECT ins.SocialMediaId, s.PlatformName,   CAST(SUM(ins.Reactions) AS UNSIGNED) AS Reactions, CAST(SUM(ins.Comments) AS UNSIGNED) AS Comments, CAST(SUM(ins.Shares) AS UNSIGNED) AS Shares,CAST(SUM(ins.Views) AS UNSIGNED) AS Views FROM campaigninfo cinf INNER JOIN campaigndetail cd ON cinf.CampaignInfoId = cd.CampaignInfoId INNER JOIN insights ins ON ins.CampaignDetailId = cd.CampaignDetailId INNER JOIN socialmedia s ON ins.SocialMediaId = s.SocialMediaId WHERE cinf.CampaignInfoId = %s GROUP BY ins.SocialMediaId, s.PlatformName", (CampaignInfoId,))
            result = cursor.fetchall()

        if result:
            column_names = [col[0] for col in cursor.description]
            campaigninsights = [dict(zip(column_names, row)) for row in result]
            for insight in campaigninsights:
                del insight['SocialMediaId']
            data = {'campaigninsights': campaigninsights}
            response = {'status': True, 'message': 'Success', 'code': 200, 'data': data}
        else:
            data = {'campaigninsights': []}
            response = {'status': True, 'message': 'No Record Found', 'code': 200, 'data': data }
        return make_response(encrypt_data(response), 200)

    except Exception as e:
        response = {'status': False, 'message': str(e), 'code': 400, 'data': {}}
        return make_response(encrypt_data(response), 400)


@app.route("/api/auth/brand/Wallet",methods=['POST'])
@jwt_required()
def brandWallet():
    response = {'status': '', 'message': '', 'code': '', 'data': {}}
    try:
        brand_id = request.form.get('BrandId')
        cursor = mysql.connection.cursor()

        cursor.execute("SELECT  SUM(Budget) AS budget  FROM  campaigninfo  WHERE  BrandId = %s", (brand_id,))
        budget = cursor.fetchone()[0] or 0

        cursor.execute("SELECT SUM(DepositAmount) AS deposit_amount FROM cashflowbrand WHERE BrandId = %s", (brand_id,))
        deposit_amount = cursor.fetchone()[0] or 0

        available_balance = max(deposit_amount - budget, 0)
        pending_cash_in = max(budget - deposit_amount, 0)

        data = {
            'PendingCashin': pending_cash_in,
            'AvailableBalance': available_balance,
            'LastUpdatedon': str(date.today().strftime("%d/%m/%y"))
        }

        response['status'] = True
        response['message'] = "Success"
        response['code'] = 200
        response['data'] = data

        temp = encrypt_data(response)
        return make_response(temp, 200)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        temp = encrypt_data(response)
        return make_response(temp, 400)

    finally:
        mysql.connection.commit()
        cursor.close()


@app.route("/api/auth/brand/viewTranscationHistory",methods=['POST'])
@jwt_required()
def viewBrandrTranscationHistory():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            brandId=request.form.get('BrandId')
            cursor = mysql.connection.cursor()
            query ="select  ci.CampaignName,tb.DepositAmount,tb.DepositDate from transactionbrand as tb inner join cashflowbrand as cfb on cfb.CashFlowId = tb.CashFlowId inner join campaigninfo as ci on ci.CampaignInfoId = cfb.CampaignInfoId where cfb.BrandId = %s"
            cursor.execute(query, (brandId,))
            result = cursor.fetchall()
            cursor.close()
            mysql.connection.commit()
            if not result:
                response['status'] = True
                response['message'] = "No Record"
                response['code'] = 200
                response['data'] = []
                return make_response(encrypt_data(response), 200)
            column_names = [col[0] for col in cursor.description]
            data = [dict(zip(column_names, row)) for row in result]
            for d in data:
                d['DepositDate'] = d['DepositDate'].strftime("%d/%m/%Y")
                d['Status'] = 'completed'
            response['status'] = True
            response['message'] = "Success"
            response['code'] = 200
            response['data'] = data
            return make_response(encrypt_data(response), 200)

        else:
            response['status'] = False
            response['message'] = "InValid Request"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)




@app.route("/api/auth/legal/terms",methods=['GET','POST'])
@jwt_required()
def termsAndCondition():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            data ="""<html><head></head><body><h1>Social Pigeon Terms and Conditions</h1><p>Social Pigeon Application, referred to as app, we, our, us. These terms and conditions monitor your access to and use of our services including our app, email notifications, widgets, links, and buttons. You automatically agree to the terms and conditions by signing up for Social Pigeon.</p><p> <ul> <li> <p><b>Acceptance of Terms:</b> Users are required to read, understand, and agree to the terms and conditions before using the platform or its services.</p></li><li> <p><b>User Eligibility:</b> Users must meet certain criteria (such as age restrictions) to use the platform or specific features.</p></li><li> <p><b>Account Creation:</b> Users may need to create an account, provide accurate information, and choose a secure password. They may also be responsible for maintaining the confidentiality of their account credentials.</p></li><li> <p><b>User Conduct:</b> Users are expected to comply with applicable laws and regulations and refrain from engaging in prohibited activities, such as illegal content sharing, harassment, spamming, or hacking.</p></li><li> <p><b>Intellectual Property:</b> Users are typically required to respect the intellectual property rights of the platform and other users, and they may not infringe upon copyrights, trademarks, or other proprietary rights.</p></li><li> <p><b>Content Submission:</b>Users may have the ability to submit or upload content to the platform, but they are often required to ensure the content is original, lawful, and does not violate any rights or regulations.</p></li><li> <p><b>Privacy and Data Protection:</b>The platform should outline how user data is collected, stored, and used, as well as any applicable privacy policies and data protection measures.</p></li><li> <p><b>Third-Party Links and Services:</b>If the platform provides links to third-party websites or services, it may disclaim responsibility for the content or actions of those third parties.</p></li><li> <p><b>Dispute Resolution:</b>The terms and conditions may include provisions regarding dispute resolution, such as arbitration or mediation, to settle any conflicts between the platform and users.</p></li><li> <p><b>Limitation of Liability:</b>The platform may limit its liability for any damages or losses incurred by users while using the platform's services or as a result of any disruptions or security breaches.</p></li></ul></body></html>"""
            response_data = {
                'status': True,
                'message': 'Success',
                'code': 200,
                'data': data
            }
            encrypted_data = encrypt_data(response_data)
            return make_response(encrypted_data, 200)

        response_data = {
            'status': False,
            'message': "Invalid Request",
            'code': 400,
            'data': {}
        }
        encrypted_data = encrypt_data(response_data)
        return make_response(encrypted_data, 400)


    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)



@app.route("/api/auth/legal/privacy",methods=['GET','POST'])
@jwt_required()
def privacyPolicy():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            data ="""<html><head></head><body><h1>PRIVACY POLICY</h1><p >Convex Interactive Pvt Ltd. is the sole operator of this app and is committed to protecting the privacy of its users. Therefore, it is important for you to know that any personal information collected on this app is solely intended to enhance your experience.</p><p>By using our app, you agree to our privacy policy and consent to sharing your information with us.</p><h2>How We Use Collected Information:</h2><p><strong>To improve customer service:</strong> The information you provide helps us respond to your customer service requests and support needs more efficiently.<br/><strong>To personalize the user experience:</strong> We may use information in the aggregate to understand how our users as a group utilize the services and resources provided on our site.<br/><strong>To enhance our site:</strong> We continuously strive to improve our website offerings based on the information and feedback we receive from you.<br/>To send periodic emails: We may use the email address provided to respond to inquiries, questions, and/or other requests.</p><h2>How We Protect Your Information:</h2><p>We adopt appropriate data collection, storage, and processing practices, as well as security measures, to protect against unauthorized access, alteration, disclosure, or destruction of your personal information, username, password, transaction information, and data stored on our site.</p><h2>Sharing Your Personal Information:</h2><p>We do not sell, trade, or rent users' personal identification information to others. However, we may share generic aggregated demographic information, not linked to any personal identification information, regarding visitors and users, with our business partners, trusted affiliates, and advertisers for the purposes outlined above.</p></body></html>"""
            response_data = {
                'status': True,
                'message': 'Success',
                'code': 200,
                'data': data
            }
            encrypted_data = encrypt_data(response_data)
            return make_response(encrypted_data, 200)

        response_data = {
            'status': False,
            'message': "Invalid Request",
            'code': 400,
            'data': {}
        }
        encrypted_data = encrypt_data(response_data)
        return make_response(encrypted_data, 400)


    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)

@app.route("/api/auth/support/getHelp",methods=['GET','POST'])
@jwt_required()
def GetHelp():
    response = {'status': '', 'message': '', 'code': '', 'data': ''}
    try:
        if request.method == "POST":
            data = []

            Opportunities = """<html><head></head><body><ul><li>The AI Solutions from Social Pigeon let you choose, create, and manage your campaign.</li><li>All recommendations are tailored to your budget, preferred platform, and sector. </li><li>Customised and interactive dashboards with 360-degree views.</li><li>Management, tracking, and analysis of campaigns.</li><li>AI Suggestions, Influencer Matching, and Search. </li><li>Continuous Live Chat Support & Help Center.</li><li>Streamlined payments and processes Across-the-country variety of brands and possibilities.</li></ul></body></html>"""
            QA = ("question", "answer")
            QNA = [("How does Social Pigeon work?","All the brand campaigns that are active on the platform are displayed on the Social Pigeon main page. You can access your opportunities, profile, wallet, notifications, and more from here."),
                   ("How to use it?","<html><head></head><body><p>When influencers log in to the platform, and navigate to Opporunity section they will have access to different tabs that provide a comprehensive overview of their campaigns across various platforms. These tabs include the following:</p><ul><li><strong>All Campaigns:</strong> This tab displays all campaigns available on the platform, including those in which the influencer is involved. It provides a comprehensive view of all campaigns, regardless of the influencer's specific participation.</li><li><strong>Active Campaigns:</strong> In this tab, influencers can find campaigns that are currently active and ongoing. It allows them to focus on the campaigns that require their immediate attention and engagement.</li><li><strong>Paused Campaigns:</strong> This tab showcases campaigns that have been temporarily paused. Influencers can view and manage these campaigns, making adjustments or resuming them when necessary.</li><li><strong>Waiting for Approval:</strong> This tab displays campaigns that are pending approval from relevant parties. Influencers can view the status of these campaigns and await the necessary approvals before proceeding with further actions.</li><li><strong>Completed Campaigns:</strong> The Completed Campaigns tab provides a record of campaigns that have successfully concluded. </li></ul><p>Influencers can review the details of these campaigns, including performance metrics and any associated feedback or results.Please note that while the All Campaigns tab displays all campaigns on the platform, the other tabs focus specifically on the campaigns in which the influencer is involved and provides their respective status (active, paused, or completed) against those campaigns.Similarly, when brands log in to the platform, they also have access to different tabs that offer a comprehensive view of their campaigns. These tabs include:</p><ul><li><strong>All Campaigns:</strong> Similar to influencers, the All Campaigns tab for brands displays a comprehensive list of all campaigns associated with the brand. It serves as a central hub for brands to manage and monitor their campaigns effectively.</li><li><strong>Active Campaigns:</strong> In this tab, brands can view campaigns that are currently active and ongoing. It allows them to stay up-to-date with the campaigns that are currently running and require their attention.</li><li><strong>Paused Campaigns:</strong> The Paused Campaigns tab enables brands to review and manage campaigns that have been temporarily paused. They can make adjustments or resume these campaigns as needed.</li><li><strong>Completed Campaigns:</strong> The Completed Campaigns tab provides brands with a record of campaigns that have reached their successful completion. </li></ul><p>Brands can analyze the performance of these campaigns and gain insights for future marketing strategies.By utilizing these different tabs, both influencers and brands can effectively manage and track their campaigns within the platform. The tab structure facilitates easy navigation and organization, ensuring a streamlined experience for influencers and brands alike.</p></body></html>"),
                   ("Why should I trust Social Pigeon with my personal information?","The only goal of any personal data gathered by this app is to enhance your experience. In order to properly manage your money, you can be requested for personal information while you use our app, such as your name, birthdate, and possibly even your credit card information. Please be aware that if you choose to participate in a survey, inquiry, or poll on the app, you opt to share your personal information with us as well. As a result, by using our app, you accept our privacy statement and give us access to your information."),
                   ("How do I start?","By registering as a brand or an influencer, you may begin utilising social pigeon. After signing up, you may use the app by entering the password that was sent to your email address when you logged in."),
                   ("Opportunities",Opportunities),
                   ("Payments","You can send or receive money using Social Pigeon secure payment gateway directly into your bank account."),
                   ("Troubleshooting ","for any kind of query you can contact us at info@socialpigeon.io")]
            for mqa in QNA:
                data.append(dict(zip(QA, mqa)))

            response['status'] = True
            response['message'] = 'Success'
            response['code'] = 200
            response['data'] = data
            temp = encrypt_data(response)
            return make_response(temp, 200)

        else:
            response['status'] = False
            response['message'] = "Response internet connection failure"
            response['code'] = 400
            response['data'] = {}
            temp = encrypt_data(response)
            return make_response(temp, 400)

    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
        response['code'] = 400
        response['data'] = {}
        temp = encrypt_data(response)
        return make_response(temp, 400)



if __name__ == '__main__':
    app.run('0.0.0.0',port=5003, threaded=True,debug=True)

