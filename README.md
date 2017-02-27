>最近在学习flask，用到flask-login，发现网上只有0.1版本的中文文档，看了官方已经0.4了，并且添加了一些内容，所以准备自己看英文文档，顺便翻译一下，中间有些单词或句子不懂怎么翻译，可能有歧义，请见谅。

#Flask-Login
Flask-Login提供Flask用户会话管理。他处理登录，登出和在较长的一段时间内记住你的用户会话的常用任务。

他将会：

 - 在会话中存储活动用户的ID，以及让你容易的登录和登出。
 - 让你限制视图来登录（或登出）用户。
 - 处理“记住我”的功能。
 - 帮助保护你的用户对话不被cookie小偷偷取。
 - 可能和Flask-Principal或者与其他授权扩展结合。

然而，它**不能**：

 - 强加一个特定的数据库或者其他存储方式给你。你用来负责用户如何加载。
 - 限制你使用用户名和密码，OpenIDs或者任何其他的验证方法。
 - 处理超出“登录或登出”权限之外的
 - 处理用户注册或者账号恢复
 
***
* [安装](#安装)
* [配置你的应用](#配置你的应用)
* [如何工作](#如何工作)
* [你的用户类](#你的用户类)
* [登录案例](#登录案例)
* [用户自定义登录过程](#用户自定义登录过程)
* [使用Autherization头的登录](#使用Autherization头的登录)
* [使用request_loader的自定义登录](#使用request_loader的自定义登录)
* [匿名用户](#匿名用户)
* [记住我](#记住我)
  * [可选令牌](#可选令牌)
  * [活跃登录](#活跃登录)
  * [Cookie设置](#Cookie设置)
* [会话保护](#会话保护)
* [本地化](#本地化)
* [API文档](#API文档)
  * [登录配置](#登录配置)
  * [登录机制](#登录机制)
  * [视图保护](#视图保护)
  * [用户对象辅助](#用户对象辅助)
  * [实用工具](#实用工具)
  * [标志](#标志)


***

##安装
通过pip安装扩展：

    $pip install flask-login

##配置你的应用
使用Flask-Login应用最重要的部分是[LoginManager](https://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager)类。你应该为你的应用程序创建一个这个类的代码，像这样：

    login_manager = LoginManager()

登录管理包含让你应用程序和Flask-Login一起工作的代码，例如如何通过ID加载用户，在哪里发送用户时需要登录等等。

一旦真实的应用对象被创建，你就能配置它来登录，通过：

    login_manager.init_app(app)


##如何登录
你将需要提供一个[user_loader](https://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.user_loader)回调。这个回调被用来从对话里存储的用户ID中重新加载用户对象。它应该获取用户的unicode ID，以及返回对应的用户对象。例如：

```
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)
```

他应该返回[None](https://docs.python.org/3/library/constants.html#None)（不引发异常），如果ID不是有效的。（既然那样，ID将手动地从会话中移除以及进程将会继续下去。）

##你的用户类
你用来表示用户的类需要实现这些特性和方法：

`is_authenticated`
这个特性应该返回[True](https://docs.python.org/3/library/constants.html#True)，如果用户已经被认证，也就是说他们已经提供有效的证明。（只有认证的用户将完成[login_required](https://flask-login.readthedocs.io/en/latest/#flask_login.login_required)标准）

`is_active`
这个特性应该返回[True](https://docs.python.org/3/library/constants.html#True)，如果这是一个除了作为身份认证的活动的用户，他们也激活了他们的账号，没有被废除，或者在任何情况你的应用程序拒绝了一个账号。不活跃的用户或许不能登录进去（除了被强制的过程）。

`is_anonymous`
这个特性应该返回[True](https://docs.python.org/3/library/constants.html#True)，如果这是一个匿名用户。（实际用户应该返回[False](https://docs.python.org/3/library/constants.html#False)来代替）

`get_id()`
这个方法必须返回一个唯一标识该用户的unicode，以及可能被用来从[user_loader](https://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.user_loader)回调来加载用户。注意这个必须是unicode字符，如果ID是原始的int类型或者一些其他类型，你将需要转换它变成unicode字符。

---

要更容易地实现一个用户类，你可以继承[UserMixin](https://flask-login.readthedocs.io/en/latest/#flask_login.UserMixin)方法，它可以提供默认的对于所有这些特性和方法的实现。（即使这不是必须的。）

##登录案例
一旦用户认证后，你将从[login_user](https://flask-login.readthedocs.io/en/latest/#flask_login.login_user)函数登录他们。
例如：
```
@app.route('/login',methods=['GET','POST'])
def login():
    #这里我们使用一个类，从数据中来表示和认证我们的客户端
    #例如，WTForms是一个库，可以为我们处理这些，我们可以使用自定义的LoginForm来认证。
    form = LoginForm()
    if form.validate_on_submit():
        #登录和认证用户
        #用户应该实例化你的`User`类
        login_user(user)
        
        flask.flash('logged in successfully')
        
        next = flask.request.args.get('next')
        #is_safe_url用来检查是否url是重定向安全的
        #查看http://flask.pocoo.org/snippets/62/的一个例子
        if not is_safe_url(next):
            return flask.abort(400)
        
        return flask.redirect(next or flask.url_for('index'))
    return flask.render_template('login.html',form=form)
```
*警告*:你**必须**验证下一个参数的值。如果你不那么做的话，你的应用程序将会容易被重定向攻击。查看[this Flask Snippet](http://flask.pocoo.org/snippets/62/)一个例子实现is_safe_url。

就是这么简单。你可以访问登录的用户使用[current_user](https://flask-login.readthedocs.io/en/latest/#flask_login.current_user)代理，这个可以在所有template中使用：
```
{% if current_user.is_authenticated %}
    Hi {{cuttent_user.name}}
{% endif %}
```

查看被允许登录的用户可以被[login_required](https://flask-login.readthedocs.io/en/latest/#flask_login.login_required)修饰器修饰：
```
@app.route("/settings")
@login_required
def settings():
    pass
```

当用户准备登出时：
```
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(somewhere)
```

他们将会被登出，以及所有他们会话的cookies会被清除。

##用户自定义登录过程
默认的，当一个用户视图访问一个[login_required](http://flask-login.readthedocs.io/en/latest/#flask_login.login_required)视图而不登录时，Flask-Login将会通过flash工具传出一个信息然后将他们重定向到登录视图。（如果登录没有设置，将会报401错误）

可以通过[LoginManager.login_view](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.login_view)来设置登陆视图。下面是一个例子：

    login_manager.login_view = "user.login"

默认flash工具发出的信息是`Please log in to access this page`。可以通过设置[LoginManager.login_message](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.login_message)来自定义这段信息：

    login_manager.login_message = u"this is ZZES xiaobaicai"

通过**LoginManager.login_message_category**，自定义消息类型:

    login_manager.login_message_category = "info"

当登录视图被重定向，它将会有一个查询字符串中的`next`变量，是用户试图访问的页面。非此即彼，如果**USE_SESSION_FOR_NEXT**是[True](https://docs.python.org/3/library/constants.html#True)，页面在会话中的`next`键值下存储。

如果你想要更进一步的自定义进程，可以用[LoginManager.unauthorized_handler](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.unauthorized_handler)来修饰函数：
```
@login_manager.unauthorized_handler
def unauthorized():
    #do stuff
    return a_response
```

##使用Autherization头的登录
>###警告：
这个方法被废弃了；使用**request_loader**(下一节介绍)代替。

有些时候你想使用**Authorization**头来支持基本认证登录，例如api请求。你需要提供一个[header_loader](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.header_loader)回调，来支持登录认证头部。这个回调应该和你的[user_loader](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.user_loader)回调一样，除了他接受一个头部值而不是用户ID。下面是一个例子：
```
@login_manager.header_loader
def load_user_from_header(header_val):
    header_val = header_val.replace('Basic', '', 1)
    try:
        header_val = base64.b64decode(header_val)
    except TypeError:
        pass
    return User.query.filter_by(api_key = header_val).first()
```

默认的**Authorization**头部的值是传递给你的[header_loader](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.header_loader)回调。你可以通过**AUTH_HEADER_NAME**来改变头部。

##使用request_loader的自定义登录
有些时候你不想使用cookies来登录用户，例如使用头部值或者一个作为查询参数传递的api键。在这些情况下，你应该使用**request_loader**回调。这个回调和你的[user_loader](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.user_loader)回调一样，除了它是接受Flask请求而不是用户ID。

举个例子，同时支持url参数和和使用**Authorization**头部的基础认证的登录：
```
@login_manager.request_loader
def load_user_from_request(request):
    #第一，尝试使用api_key的url参数来登录
    api_key = request.args.get('api_key')
    if api_key:
        user = User.query.filter_by(api_key=api_key).first()
        if user:
            return uesr
    
    #然后，使用基础认证来登录
    api_key = request.headers.get('Authorization')
    if api_key:
        api_key = api_key.replace('Basic ', '', 1)
        try:
            api_key = base64.b64decode(api_key)
        except TypeError:
            pass
        user = User.query.filter_by(api_key = api_key).first()
        if user:
            return user
    #最后，如果两个方法都没有登录用户，则返回None
    return None
```

##匿名用户
默认的，当一个用户没实质上登录，[current_user](http://flask-login.readthedocs.io/en/latest/#flask_login.current_user)被设置成一个[AnonymousUserMixin](http://flask-login.readthedocs.io/en/latest/#flask_login.AnonymousUserMixin)对象。它有下列属性和方法：

 - **is_active**和**is_authenticated**是[False](https://docs.python.org/3/library/constants.html#False)
 - **is_anonymous**是[True](https://docs.python.org/3/library/constants.html#True)
 - **get_id()**返回[None](https://docs.python.org/3/library/constants.html#None)

如果你有自定义匿名用户的需求（例如，他们需要有一个权限字段），你可以提供一个可调用的对象（一个类或者一个工厂模式函数），通过[LoginManager](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager)来创建匿名用户:

    login_manager.anonymous_user = MyAnonymousUser

##记住我
默认的，当用户关闭浏览器时，Flask Session会被删除，用户会被登出。“记住我”防止了用户关闭他们浏览器时，不小心登出的现象。这个意思**不是**在用户登出后，在登录框中记住或者预填写用户的用户名或者密码。

“记住我”功能可能很难实现。然而，Flask-Login让它几乎透明了--只用将`remember=True`传递给[login_user](http://flask-login.readthedocs.io/en/latest/#flask_login.login_user)调用。一个cookie将会保存到用户的电脑，然后Flask-Login将会自动地从那个cookie保存用户ID，如果它不在会话中的话。cookie是可防护的，所以如果用户篡改它（也就是说插入别人的用户ID代替他们自己的），cookie只会被拒绝，如果它不存在的话。

这个等级的功能是自动处理的。然而你能（以及应该，如果你的应用程序处理各种各样的敏感数据）提供额外的基础设施来增加你记住cookies的安全性。

###可选令牌
使用用户ID作为记住的令牌值意思是你必须改变用户ID来使他们的登录会话无效。一种提升的方式是使用一个可替换的会话令牌代替用户ID。下面是一个例子：
```
@login_manager.user_loader
def load_user(session_token):
    return User.query.filter_by(session_token=session_token).first()
```

然后你用户类的**get_id**方法将会返回一个会话令牌代替用户ID：
```
def get_id(self):
    return unnicode(self.session_token)
```

这个方法可以让你自由地改变用户会话令牌为一个新的自动生成的值，当用户改变他们的密码时要确定他们的旧的认证会话停止并无效。注意会话令牌必须一直唯一标识用户。。。可以认为它为第二个用户ID

###活跃登录
当用户登录时，他们的对话会被标记为“活跃”，表明他们确实在已认证的会话上。当他们的会话被销毁且他们通过“记住我”cookie登录回来时，会被标记为“不活跃”。[login_required](http://flask-login.readthedocs.io/en/latest/#flask_login.login_required)不区分活跃，对大部分页面友好。然而，敏感的行为比如改变一个私人信息，则需要活跃登录。（像修改密码这样的操作总是需要密码，无论是否重登入。）

[fresh_login_required](http://flask-login.readthedocs.io/en/latest/#flask_login.fresh_login_required)，除了验证用户已经登录，也将确定他们是活跃登录。如果不是，将会把他们发送到一个页面，在那里他们可以重新输入他们的认证信息。你可以自定义这个行为和你自定义[login_required](http://flask-login.readthedocs.io/en/latest/#flask_login.login_required)的方法一样，通过设置[LoginManager.refresh_view](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.refresh_view)，[needs_refresh_message](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.needs_refresh_message)，以及**needs_refresh_message_category**：

```
login_manager.refresh_view = "accounts.reauthenticate"
login_manager.needs_refresh_message = (
    u"为了保护你的账号，请重新访问这个页面"
)
login_manager.needs_refresh_message_category = "info"
```

或者提供你自己的回调来处理活跃刷新:
```
@login_manager.needs_refresh_handler
def refresh():
    #do stuff
    return a_response
```
调用[confirm_login](http://flask-login.readthedocs.io/en/latest/#flask_login.confirm_login)函数，重新把会话标记为活跃的。

###Cookie设置
可以在应用程序设置里自定义cookie细节。

|REMEMBER_COOKIE_NAME|储存“记住我”信息的cookie名。**默认：**`remember_token`|
|---|---|
|REMEMBER_COOKIE_DURATION|cookie到期的时间量，作为[datetime.timedelta](https://docs.python.org/3/library/datetime.html#datetime.timedelta)对象。**默认：**365天（一个非润阳历年）|
|REMEMBER_COOKIE_DOMAIN|如果“记住我”的cookie要跨域，那么在这里设置域名值（也就是说`.example.com`将会允许cookie用于所有`example.com`的二级域名）默认：[None](https://docs.python.org/3/library/constants.html#None)|
|REMEMBER_COOKIE_PATH|限制“记住我”cookie在一个确定的路径，**默认：**/|
|REMEMBER_COOKIE_SECURE|限制“记住我”cookie安全通道范围（通常是HTTPS）。**Default：**[None](https://docs.python.org/3/library/constants.html#None)|
|REMEMBER_COOKIE_HTTPONLY|防止“记住我”cookie被通过客户端脚本访问。**默认：**[False](https://docs.python.org/3/library/constants.html#False)|

##会话保护
虽然上述特性保护了你的“记住我”令牌不被cookie小偷获取，但是会话cookie依然容易被攻击。Flask-Login包括了会话保护来帮助你保护用户的会话，使其不被偷取。

你可以在[LoginManager](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager)和在app配置中配置会话保护。如果被开启，它可以运行在**基本**或者**强大**模式。在[LoginManager](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager)设置它，设置**session_protection**为“basic”或者“strong”：

    login_manager.session_protection = "strong"

或者停用它：

    login_manager.session_protection = None

默认的，它被激活为“basic”模式。可以在app配置中将其关闭，通过设置**SESSION_PROTECTION**为[None](https://docs.python.org/3/library/constants.html#None)、“basic”或者“strong”。

当会话保护是开启的，每个请求，都为用户电脑生成一个标识符（基本的是IP地址和用户代理的MD5 hash值）。如果会话不一个相关的标识符，将从储存生成一个。如果它有一个标识符，以及它匹配一个生成的，则请求为OK。

如果标识符在**基本**模式下不能被匹配，或者当会话是永久的，然后会话将会很简单的被标记成non-fresh 以及任何活跃登录的需求，任何需要活跃登录的东西都会强制要求用户来重新认证。（当然，你必须使用了活跃登录登入机制）

如果标识符在**strong**模式不能匹配非永久会话，然后整个会话（并且记住我令牌 如果它是存在的）会被删除。

##本地化
默认的，[LoginManager](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager)使用`flash`去展示信息当用户需要登录时。这些信息是英文的。如果你需要本地化，设置[LoginManager](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager)的**localize_callback**属性为一个函数去调用这些信息在他们被发送到`flash`之前，例如`gettext`.这个函数将会调用信息以及会返回一个数值发送到`flash`.

##API文档
这个文档是从Flask-Login源代码中自动生成的

###登录配置
`flask_login`.**LoginManager**(*app=None,add_context_processor=True*)[[source](http://flask-login.readthedocs.io/en/latest/_modules/flask_login/login_manager.html#LoginManager)] 
>这个对象被用于保存登录用的设置。[LoginManager](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager)的实例不会绑定到特殊程序，所以你可以在你代码的关键部位创建它，然后绑定它到你的程序的工厂模式函数中。

**setup_app**(*app,add_context_processor=True*)[[source](http://flask-login.readthedocs.io/en/latest/_modules/flask_login/login_manager.html#LoginManager.setup_app)]
>这个方法已经被废除，请使用**LoginManager.init_app()**代替。

**unauthorized()** [[source]](http://flask-login.readthedocs.io/en/latest/_modules/flask_login/login_manager.html#LoginManager.unauthorized)
>这个会在用户需要登录的时候调用。如果你用[LoginManager.unauthorized_handler](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.unauthorized_handler)注册一个回调，之后它会被调用。否则，它将发生如下行为：
>
 - 给用户Flash弹出[LoginManager.login_message](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.login_message)
 - 如果应用使用蓝图发现登录视图当前的蓝图使用**blueprint_login_views**。如果app没有使用蓝图或者登录视图当前的蓝图没有特别的使用[login_view](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.login_view)的值。
 - 重定向用户到登录视图。（他们试图进入的页面将会被传输到`next`查询字符串变量中，所以你可以重定向那里如果呈现的不是首页。非此即彼，它将会被添加到会话，如果**USE_SESSION_FOR_NEXT**被设置。）

>如果[LoginManager.login_view](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.login_view)没有被定义，然后他将简单的弹出HTTP 401（Unauthorized）错误代替。
这应该返回一个视图或者before/after_request函数，否则重定向会没有用。

**needs_refresh()**[[source]](http://flask-login.readthedocs.io/en/latest/_modules/flask_login/login_manager.html#LoginManager.needs_refresh)
>这个当用户登录时被调用，但是他们需要重新被认证，因为他们的会话是无效的。如果你使用[needs_refresh_handler](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.needs_refresh_handler)http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.needs_refresh_handler注册一个回调，随后它就会被调用。否则它会发生下列行为：
>
 - 给用户Flash弹出[LoginManager.needs_refresh_message](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.needs_refresh_message)
 - 重定向用户到[LoginManager.refresh_view](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.refresh_view)。（他们试图进入的页面将会被传输到`next`查询字符串变量中，所以你可以重定向那里如果呈现的不是首页。。）
 

>如果[LoginManager.refresh_view](http://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.refresh_view)没有被定义，然后他将简单的弹出HTTP 401（Unauthorized）错误代替。
这应该返回一个视图或者before/after_request函数，否则重定向会没有用。

**常规配置**

**user_loader**(*callback*)[[source]](http://flask-login.readthedocs.io/en/latest/_modules/flask_login/login_manager.html#LoginManager.user_loader)
>这个为设置回调再次从会话加载用户。你设置的函数应该需要一个用户ID（`unicode`）以及返回一个用户对象，或者如果用户不存在的话返回`None`。
**参数：** **回调**（[callable](https://docs.python.org/3/library/functions.html#callable)）——回调检索用户对象。

**header_loader**(*callback*)  [[source]](http://flask-login.readthedocs.io/en/latest/_modules/flask_login/login_manager.html#LoginManager.header_loader)
>这个函数被废弃了，请使用**LoginManager.request_loader()**代替。
这个回调设置来从头部值加载用户。这个函数你设置应该需要一个认证令牌以及返回一个用户对象，或者用户不存在时返回`None`.
**参数：** **回调**（[callable](https://docs.python.org/3/library/functions.html#callable)）——回调检索用户对象。























