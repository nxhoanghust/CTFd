from flask import render_template, Blueprint
from flask import request, session, abort, make_response, jsonify
import datetime
import binascii
import rsa
import re, json
import flask

from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES, CTFdStandardChallenge
from CTFd.plugins.flags import FlagException, get_flag_class
from CTFd.models import db, Challenges, Flags, Submissions
# from CTFd.plugins.keys import BaseKey, KEY_CLASSES
from CTFd.utils.decorators import admins_only, is_admin

from CTFd.utils.uploads import upload_file, delete_file
prefix = "VCS{"
flag_format = r"Vc5P4sSP0rt_(\d{10})"
online = Blueprint('onlinechallenge', __name__, template_folder="templates")

def validate_internal(flag):
    m = re.match(flag_format, flag)
    tm = m.group(1)
    curr = int(datetime.datetime.utcnow().timestamp())
    if m and tm and int(tm) < curr and int(tm) > curr - 60*60*3: 
        return True
    return False

def validate_flag(row, flag):
    if flag.startswith(prefix) and len(flag) == (129 + len(prefix)):
        flag = flag.lstrip(prefix).rstrip("}")
        privkey = row.privkey
        try:
            flag_encoded = binascii.unhexlify(flag)
            if privkey != "":
                keyblob = rsa.PrivateKey.load_pkcs1(privkey.encode())
                raw_flag = rsa.decrypt(flag_encoded, keyblob).decode()
                if raw_flag and validate_internal(raw_flag):
                    return True
                else: 
                    return False
        except Exception as e:
            print(e)
    return False

def validate_pkcs1_key(key_data):
    try:
        # Attempt to load the key
        private_key = rsa.PrivateKey.load_pkcs1(key_data.encode())
        # print("The key is a valid PKCS#1 private key.")
        return private_key
    except ValueError:
        print("Invalid PKCS#1 private key format.")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

class CTFdOnlineChallenge(Challenges):
    __mapper_args__ = {'polymorphic_identity': 'online'}
    id = db.Column(None, db.ForeignKey('challenges.id', ondelete="CASCADE"), primary_key=True)
    privkey = db.Column(db.String(80))
    pubkey = db.Column(db.String(80))

    def __init__(self, *args, **kwargs):
        super(CTFdOnlineChallenge, self).__init__(**kwargs)

class CheatTeam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chal = db.Column(db.String)
    cheat = db.Column(db.String)
    cheatd = db.Column(db.String)

    date = db.Column(db.String(40),default=datetime.datetime.utcnow)
    flag = db.Column(db.String(40))

    def __init__(self,chal,cheat,cheatd,flag):
        self.chal = chal
        self.cheat = cheat
        self.cheatd = cheatd
        self.flag = flag

class OnlineTypeChallenge(CTFdStandardChallenge):
    id = 'online'
    name = 'online'
    templates = {  # Handlebars templates used for each aspect of challenge editing & viewing
        # 'create': '/plugins/dynamic_flag_challenges/assets/online-challenge-create.njk',
        'create': '/plugins/dynamic_flag_challenges/assets/create.html',
        'update': '/plugins/dynamic_flag_challenges/assets/update.html',
        'view' : '/plugins/dynamic_flag_challenges/assets/view.html',
    }
    scripts = {  # Scripts that are loaded when a template is loaded
        'create': '/plugins/dynamic_flag_challenges/assets/online-challenge-create.js',
        'update': '/plugins/dynamic_flag_challenges/assets/online-challenge-update.js',
        'view' : '/plugins/dynamic_challenges/assets/view.js',
    }
    route = "/plugins/dynamic_flag_challenges/assets/"

    blueprint = Blueprint(
        "dynamic_flag_challenges",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )
    @staticmethod
    def create(request):
        """
        This method is used to process the challenge creation request.

        :param request:
        :return:
        """
        data = request.form or request.get_json()
        privkey = data.get("privkey")
        if not privkey:
            publicKey, privateKey = rsa.newkeys(512)
            data["privkey"] = privateKey.save_pkcs1().decode()
            data["pubkey"] = publicKey.save_pkcs1().decode()
            # data = publicKey.save_pkcs1()
        # HOANGNX: validate the privkey
        else:
            privblob = validate_pkcs1_key(privkey)
            if not privblob:
                return {"errors": "Invalid Private Key"}
            else:
                print(privblob.PublicKey.save_pkcs1().decode())
                data["pubkey"] = privblob.PublicKey.save_pkcs1().decode()
        challenge = CTFdOnlineChallenge(**data)


        db.session.add(challenge)
        db.session.commit()
        return challenge

    @staticmethod
    def attempt(challenge, request):
        data = request.form or request.get_json()
        submission = data["submission"].strip()
        # Check valid first before check banned
        # flags = Flags.query.filter_by(challenge_id=challenge.id).all()
        rows = CTFdOnlineChallenge.query.filter_by(id=challenge.id).all()
        for row in rows:
            try:
                if validate_flag(row, submission): # check flag
                    cheatd = Submissions.query.filter_by(challenge_id=challenge.id, type="correct",provided=submission).first()
                    print(cheatd)
                    if cheatd != None:
                        find = CheatTeam(
                                chal=cheatd.challenge_id,
                                cheat=cheatd.user_id,
                                cheatd=session['id'],
                                flag=submission
                        )
                        db.session.add(find)
                        db.session.commit()
                        return False, 'Warning, you must be copy others\'s flag!'
                    return True, "Correct"
            except FlagException as e:
                return False, str(e)
        return False, "Incorrect"

def client(**kwargs):
    """
    Return data to client
    :param kwargs:
    :return: dict
    """
    return {
        'check'    : kwargs.get('check', False),
        'reason'   : kwargs.get('reason'),
        'flag_old' : kwargs.get('flag_old'),
        'flag_new' : kwargs.get('flag_new'),
        'timestamp': kwargs.get('time')
    }
def log(state = None,content=None,path='onlineChallenge.log'):
    class Templete:
        pass
    path = os.path.join(Config.LOG_FOLDER,path) # CTFd/logs/onlineChallenge.log
    line = "[{}] <{}> {}\n".format(arrow.now().format(),request.remote_addr,request.args)
    with open(path,'a') as f:
        f.write(line)

@online.route('/admin/cheaters',methods=['GET'])
@admins_only
def show_cheat():
    if request.method == 'GET':
        cheats = CheatTeam.query.all()
        return render_template('cheat.html',cheats=cheats)


def load(app):
    app.db.create_all()
    # KEY_CLASSES['online'] = OnlineKey
    CHALLENGE_CLASSES['online'] = OnlineTypeChallenge
    app.register_blueprint(online)
    register_plugin_assets_directory(app, base_path='/plugins/dynamic_flag_challenges/assets')