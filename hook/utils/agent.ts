import "frida-il2cpp-bridge";

const SETTING = {
  Version: "2.2.81",
  IsBiliChannel: false, //是否是b服
  Proxy: true, //启用besthttp代理
  ProxyAddress: "http://192.168.0.6:8443",
  ShowEnemyHp: true, //显示敌人血量
  PP: false, //添加额外后处理
  ShowBattleTimeInfo: true, //战斗中显示时间
  SpeedLevel3: false, //战斗中三倍速
  SpeedLevel16: false, //战斗中十六倍速
  EnableTAS: true, //启用TAS和敌人信息面板
  LogToAdb: true,
  LogTag: "ArknightsHook",
  Il2CppHookDelay: 5000,
  FindFontDelay: 10000,
  GlobalFont: "Novecentowide-Normal",
  KeyBinding: {
    //按键绑定
    TAS: {
      Normal: "C",
      SingleFrame: "Alpha1",
      DoubleFrame: "Alpha2",
      PlayingOnDown: "F",
      PlayingOnUp: "R",
      CONTROL: "X",
    },
    EnemyHud: {
      ShowInfo: "Z",
    },
    BattleSpeedLevel: {
      THREE: "Alpha3",
      FOUR: "Alpha4",
    },
  },
};

const title =
  "G1szNm0gICAgX19fICAgIF9fICAgICAgICAgICAgICBfICAgICAgIF9fICAgIF9fICAgICAgG1ttChtbMzZtICAgLyAgIHwgIC8gL19fX19fX19fX19fICAoXylfX18gXy8gL18gIC8gL19fX19fXxtbbQobWzE7MzZtICAvIC98IHwgLyAvL18vIF9fXy8gX18gXC8gLyBfXyBgLyBfXyBcLyBfXy8gX19fLxtbbQobWzE7MzZtIC8gX19fIHwvICw8IC8gLyAgLyAvIC8gLyAvIC9fLyAvIC8gLyAvIC9fKF9fICApIBtbbQobWzE7MzRtL18vICB8Xy9fL3xfL18vICAvXy8gL18vXy9cX18sIC9fLyAvXy9cX18vX19fXy8gIBtbbQobWzM0bSAgICAgICAgICAgICAgICAgICAgICAgICAvX19fXy8gICAgICAgICAgICAgICAgICAbW20KG1sxOzMwbS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0bW20KG1sxOzMybUFya25pZ2h0cyBBc3Npc3QgU2NyaXB0IFYyLjAuMhtbbSAbWzQ7MzJtKEZvciBBcmtuaWdodHMgdjEuOS44MSB8IFRlc3RlZCBvbiBGcmlkYSB2MTYuMC4xMSkbW20KG1sxOzMzbUF1dGhvcmVkIGJ5IENoYW9tZW5nQ0ZYG1tt";

namespace JSUtil {
  export function hexStringTobytes(hex: string) {
    const bytes: number[] = [];
    for (let c = 0; c < hex.length; c += 2) {
      bytes.push(parseInt(hex.substring(c, 2), 16));
    }
    return bytes;
  }

  export function hexStringToPtr(hex: string) {
    const bytes = hexStringTobytes(hex);
    const ptr = Il2Cpp.alloc(bytes.length);
    ptr.writeByteArray(bytes);
    return ptr;
  }
}

function tryCallingHook(funcs: Function[], rawNames: string[], from: string) {
  for (let index = 0; index < funcs.length; index++) {
    try {
      funcs[index]();
      Logger.logWell(`${rawNames[index]}() is done.`, from);
    } catch (error: any) {
      Logger.logError(
        `An error occurred while calling ${rawNames[index]}(): ` +
          error.toString(),
        from,
      );
    }
  }
}

namespace Il2CppHook {
  let UnityEngineCoreModule: Il2Cpp.Image,
    AssemblyCSharp: Il2Cpp.Image,
    AssemblyCSharpFirstpass: Il2Cpp.Image,
    ThirdPartyAssembly: Il2Cpp.Image,
    UnityEngineUI: Il2Cpp.Image,
    UnityEngineUIModule: Il2Cpp.Image,
    UnityEnginePhysics2DModule: Il2Cpp.Image,
    CoreLib: Il2Cpp.Image;

  let Vector3: Il2Cpp.Class,
    Vector2: Il2Cpp.Class,
    Color: Il2Cpp.Class,
    UnityEngine_Input: Il2Cpp.Class,
    UnityEngine_KeyCode: Il2Cpp.Class,
    GetKeyDown: Il2Cpp.Method,
    GetKeyUp: Il2Cpp.Method,
    GetKey: Il2Cpp.Method,
    Input: Il2Cpp.Class,
    Camera: Il2Cpp.Class,
    Physics2D: Il2Cpp.Class,
    Mathf: Il2Cpp.Class,
    Enemy: Il2Cpp.Class,
    GameObject: Il2Cpp.Class,
    DataConvertUtil: Il2Cpp.Class,
    FormatUtil: Il2Cpp.Class,
    CharacterUtil: Il2Cpp.Class,
    AudioManager: Il2Cpp.Class,
    PlaySoundFx: Il2Cpp.Method;

  let BattleControllerInstance: Il2Cpp.Object | null = null;
  let UIControllerInstance: Il2Cpp.Object | null = null;

  let accountData: any, accountDataPath: string;
  let OnUIClick: () => void, OnUIEntrance: () => void;

  let Normal: Il2Cpp.Field.Type,
    SingleFrame: Il2Cpp.Field.Type,
    DoubleFrame: Il2Cpp.Field.Type,
    PlayingOnDown: Il2Cpp.Field.Type,
    PlayingOnUp: Il2Cpp.Field.Type,
    CONTROL: Il2Cpp.Field.Type,
    VISABLE: Il2Cpp.Field.Type,
    THREE: Il2Cpp.Field.Type,
    FOUR: Il2Cpp.Field.Type;

  let globalFont: Il2Cpp.Object;

  let hasPlay = false;

  function initHook(): void {
    UnityEngineCoreModule = Il2Cpp.Domain.assembly(
      "UnityEngine.CoreModule",
    ).image;
    AssemblyCSharp = Il2Cpp.Domain.assembly("Assembly-CSharp").image;
    AssemblyCSharpFirstpass = Il2Cpp.Domain.assembly(
      "Assembly-CSharp-firstpass",
    ).image;
    ThirdPartyAssembly = Il2Cpp.Domain.assembly("ThirdPartyAssembly").image;
    UnityEngineUI = Il2Cpp.Domain.assembly("UnityEngine.UI").image;
    UnityEngineUIModule = Il2Cpp.Domain.assembly("UnityEngine.UIModule").image;
    UnityEnginePhysics2DModule = Il2Cpp.Domain.assembly(
      "UnityEngine.Physics2DModule",
    ).image;
    CoreLib = Il2Cpp.Image.corlib;

    Vector3 = UnityEngineCoreModule.class("UnityEngine.Vector3");
    Vector2 = UnityEngineCoreModule.class("UnityEngine.Vector2");
    Color = UnityEngineCoreModule.class("UnityEngine.Color");

    UnityEngine_Input = UnityEngineCoreModule.class("UnityEngine.Input");
    UnityEngine_KeyCode = UnityEngineCoreModule.class("UnityEngine.KeyCode");
    GetKeyDown = UnityEngine_Input.method<boolean>("GetKeyDown");
    GetKeyUp = UnityEngine_Input.method<boolean>("GetKeyUp");
    GetKey = UnityEngine_Input.method<boolean>("GetKey");
    Input = UnityEngineCoreModule.class("UnityEngine.Input");
    Camera = UnityEngineCoreModule.class("UnityEngine.Camera");
    Physics2D = UnityEnginePhysics2DModule.class("UnityEngine.Physics2D");
    Mathf = UnityEngineCoreModule.class("UnityEngine.Mathf");
    Enemy = AssemblyCSharp.class("Torappu.Battle.Enemy");
    GameObject = UnityEngineCoreModule.class("UnityEngine.GameObject");
    DataConvertUtil = AssemblyCSharp.class("Torappu.DataConvertUtil");
    FormatUtil = AssemblyCSharp.class("Torappu.FormatUtil");
    CharacterUtil = AssemblyCSharp.class("Torappu.CharacterUtil");
    AudioManager = AssemblyCSharp.class("Torappu.AudioManager");
    PlaySoundFx = AudioManager.method("PlaySoundFx");

    const FX_UI = AudioManager.nested("FXCategory").field("FX_UI").value;
    OnUIClick = () => {
      PlaySoundFx.invoke(
        Il2Cpp.String.from("Audio/Sound_Beta_2/General/g_ui/g_ui_btn_n"),
        1.0,
        0.0,
        false,
        FX_UI,
        false,
        ptr(0),
      );
    };
    OnUIEntrance = () => {
      PlaySoundFx.invoke(
        Il2Cpp.String.from("Audio/Sound_beta_2/General/g_ui/g_ui_pageentrance"),
        1.0,
        0.0,
        false,
        FX_UI,
        false,
        ptr(0),
      );
    };

    Normal = UnityEngine_KeyCode.field("C").value;
    SingleFrame = UnityEngine_KeyCode.field("Alpha1").value;
    DoubleFrame = UnityEngine_KeyCode.field("Alpha2").value;
    PlayingOnDown = UnityEngine_KeyCode.field("F").value;
    PlayingOnUp = UnityEngine_KeyCode.field("R").value;
    CONTROL = UnityEngine_KeyCode.field("X").value;
    VISABLE = UnityEngine_KeyCode.field("Z").value;
    THREE = UnityEngine_KeyCode.field("Alpha3").value;
    FOUR = UnityEngine_KeyCode.field("Alpha4").value;
  }

  function initAccountData(): void {
    accountDataPath = Il2Cpp.applicationDataPath + "/accountData.cfx.json";
    if (!FileUtil.isFileExists(accountDataPath)) {
      FileUtil.writeFile(
        accountDataPath,
        '{"ShowHp":false,"Proxy":{"enable":false,"address":"http://x.x.x.x:port"},"Channel":{},"Game":{}}',
      );
    }
    accountData = JSON.parse(
      FileUtil.readFile(accountDataPath).content as string,
    );
  }

  function readAccountData(): void {
    accountData = JSON.parse(
      FileUtil.readFile(accountDataPath).content as string,
    );
  }

  function saveAccountData(): void {
    FileUtil.writeFile(accountDataPath, JSON.stringify(accountData));
  }

  function NetworkHook(): void {
    if (SETTING["Proxy"] || accountData["Proxy"]["enable"]) {
      Il2CppUtil.traceClass(
        AssemblyCSharp.class("Torappu.Network.NetworkRouter"),
      );
      const url = SETTING["Proxy"]
        ? SETTING["ProxyAddress"]
        : accountData["Proxy"]["address"];
      const uri = Il2CppUtil.instantiateOverload(
        Il2Cpp.Domain.assembly("System").image.class("System.Uri"),
        ["System.String"],
        Il2Cpp.String.from(url),
      );
      const proxy = Il2CppUtil.instantiateOverload(
        ThirdPartyAssembly.class("BestHTTP.HTTPProxy"),
        [
          "System.Uri",
          "BestHTTP.Authentication.Credentials",
          "System.Boolean",
          "System.Boolean",
          "System.Boolean",
        ],
        uri,
        ptr(0),
        true,
        true,
        false,
      );
      ThirdPartyAssembly.class("BestHTTP.HTTPManager")
        .method("set_Proxy")
        .invoke(proxy);
      Logger.logWell(
        `Global proxy has been set to: [1;36m${url}[m`,
        "[Il2CppHook]>[NetworkHook]",
      );
      AssemblyCSharp.class(
        "Torappu.Network.Certificate.CertificateHandlerFactory",
      )
        .nested("BouncyCastleCertVerifyer")
        .method<boolean>("IsValid").implementation = function (
        targetUri: Il2Cpp.Object,
        certs: any,
      ) {
        const host = targetUri
          .method<Il2Cpp.String>("get_Host")
          .invoke().content;
        return host != "ak.hypergryph.com";
      };
      Java.perform(function () {
        const sdk = Java.use(
          "com.hypergryph.platform.hgsdk.contants.SDKConst$UrlInfo",
        );
        sdk.getRemoteUrl.implementation = function () {
          Logger.log("[Java Layer]Changed Hypergryph SDK");
          return `${url}`;
        };
        const sdk2 = Java.use(
          "com.hypergryph.platform.hguseragreement.contans.SDKConst$UrlInfo",
        );
        sdk2.getRemoteUrl.implementation = function () {
          Logger.log("[Java Layer]Changed Hypergryph user agreement");
          return `${url}`;
        };
      });
      Il2Cpp.perform(function () {
        const Networker = AssemblyCSharp.class("Torappu.Network.Networker");
        const GetOverrideRouterUrl = Networker.method<Il2Cpp.String>(
          "get_overrideRouterUrl",
        );
        GetOverrideRouterUrl.implementation = function (): Il2Cpp.String {
          Logger.log("[Il2Cpp Layer]Changed netwprk config");
          return Il2Cpp.String.from(
            `${url}/config/prod/official/network_config`,
          );
        };
      });
    }
  }

  function MiscHook(): void {
    const LoadApplicationSign = AssemblyCSharp.class(
      "Torappu.NativeUtil",
    ).method<Il2Cpp.String>("LoadApplicationSign");
    LoadApplicationSign.implementation = function () {
      return Il2Cpp.String.from("4502A02A00395DEC05A4134AD593224D");
    };
    const VerifySignMD5RSA =
      AssemblyCSharp.class("Torappu.CryptUtils").method<boolean>(
        "VerifySignMD5RSA",
      );
    //@ts-ignore
    VerifySignMD5RSA.implementation = function (
      a: Il2Cpp.String,
      b: Il2Cpp.String,
      c: Il2Cpp.String,
    ): boolean {
      //log("[Il2Cpp Layer]Hooked VerifySignMD5RSA")
      return true;
    };
  }

  function LogHook(): void {
    const UnityEngine_Application = UnityEngineCoreModule.class(
      "UnityEngine.Application",
    );
    const CallLogCallback = UnityEngine_Application.method("CallLogCallback");
    const UnityEngine_LogType = UnityEngineCoreModule.class(
      "UnityEngine.LogType",
    );
    Interceptor.attach(
      Il2CppUtil.getFunctionByAddress(
        Il2Cpp.module,
        CallLogCallback.relativeVirtualAddress,
      ),
      {
        onEnter: (args) => {
          const name = Il2CppUtil.getEnumName(
            args[3].toInt32(),
            UnityEngine_LogType,
          );
          let color = "m";
          switch (name) {
            case "Error":
              color = "31m";
              break;
            case "Assert":
              color = "36m";
              break;
            case "Warning":
              color = "33m";
              break;
            case "Log":
              color = "34m";
              break;
            case "Exception":
              color = "31;43m";
              break;
          }
          Logger.log(
            "[1;" +
              color +
              "<" +
              name +
              "> from Unity" +
              ":\n" +
              Il2CppUtil.readCSharpString(args[1])?.replace(
                /<\/*color.*?>/g,
                "",
              ) +
              "[m\n    " +
              "[1;30m" +
              Il2CppUtil.readCSharpString(args[2])?.replace(/\n/g, "\n    ") +
              "[m",
          );
        },
      },
    );
  }

  function EnemyHpSliderHook(): void {
    const mode = AssemblyCSharp.class("Torappu.UI.UITextSlider")
      .nested("TextMode")
      .field("A_SLASH_B");

    AssemblyCSharp.class("Torappu.Battle.UI.UIUnitHUD").method(
      "Awake",
    ).implementation = function () {
      this.method("Awake").invoke();
      const hp = this.field("_hpSlider").value as Il2Cpp.Object;
      const obj: Il2Cpp.Object = Il2CppUtil.instantiate(
        UnityEngineCoreModule.class("UnityEngine.GameObject"),
        Il2Cpp.String.from("Text(Clone)"),
      );
      obj
        .method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method("SetParent")
        .invoke(hp.method<Il2Cpp.Object>("get_transform").invoke());
      const text = obj
        .method<Il2Cpp.Object>("AddComponent")
        .invoke(UnityEngineUI.class("UnityEngine.UI.Text").type.object);
      const rect = obj
        .method<Il2Cpp.Object>("GetComponent")
        .invoke(
          UnityEngineCoreModule.class("UnityEngine.RectTransform").type.object,
        );
      rect
        .method("set_anchoredPosition3D")
        .invoke(Il2CppUtil.instantiate(Vector3, 155, -15, 0).unbox());
      rect
        .method("set_localScale")
        .invoke(Vector3.method<Il2Cpp.ValueType>("get_one").invoke());
      rect
        .method("set_sizeDelta")
        .invoke(Il2CppUtil.instantiate(Vector2, 400, 20).unbox());
      text.method("set_font").invoke(globalFont);
      text.method("set_fontSize").invoke(16);
      text.field("m_Color").value = Il2CppUtil.instantiateOverload(
        Color,
        ["System.Single", "System.Single", "System.Single", "System.Single"],
        1,
        0,
        0,
        1,
      ).unbox();
      hp.field("_text").value = text;
      hp.field("_textMode").value = mode.value;
    };

    AssemblyCSharp.class("Torappu.Battle.UI.UIUnitHUD").method(
      "Attach",
    ).implementation = function (owner: Il2Cpp.Object) {
      const text = (
        (this.field("_hpSlider").value as Il2Cpp.Object).field("_text")
          .value as Il2Cpp.Object
      )
        .method<Il2Cpp.Object>("get_gameObject")
        .invoke();
      text
        .method("SetActive")
        .invoke(
          owner.class.type !=
            AssemblyCSharp.class("Torappu.Battle.Character").type &&
            owner.class.type !=
              AssemblyCSharp.class("Torappu.Battle.Token").type,
        );
      this.method("Attach").invoke(owner);
    };
  }

  function UIBaseHook(): void {
    setTimeout(() => {
      const fonts = UnityEngineCoreModule.class("UnityEngine.Resources")
        .method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll")
        .invoke(
          Il2Cpp.Domain.assembly("UnityEngine.TextRenderingModule").image.class(
            "UnityEngine.Font",
          ).type.object,
        );
      for (let index = 0; index < fonts.length; index++) {
        const f = fonts.get(index);
        if (f.toString() == SETTING["GlobalFont"] + " (UnityEngine.Font)") {
          globalFont = f;
          Logger.logWell(
            `Using Font: [1;36m${globalFont.toString()}[m`,
            "[Il2CppHook]>[UIBaseHook]",
          );
        }
      }
    }, SETTING["FindFontDelay"]);

    if (SETTING["ShowEnemyHp"] || accountData["ShowHp"]) {
      try {
        EnemyHpSliderHook();
        Logger.logWell("EnemyHpSliderHook() is done.", "[Il2CppHook]");
      } catch (error: any) {
        Logger.logError(
          "An error occurred while calling EnemyHpSliderHook(): " +
            error.toString(),
          "[Il2CppHook]",
        );
      }
    }
  }

  function PPHook(): void {
    const Postprocessing = Il2Cpp.Domain.assembly(
      "Unity.Postprocessing.Runtime",
    ).image;
    const obj = UnityEngineCoreModule.class("UnityEngine.GameObject")
      .method<Il2Cpp.Object>("FindObjectOfType")
      .inflate(
        Postprocessing.class(
          "UnityEngine.Rendering.PostProcessing.PostProcessVolume",
        ),
      )
      .invoke();
    if (!obj.isNull()) {
      Logger.logNormal("Found PostProcessVolume.", "[Il2CppHook]>[PPHook]");
      const profile = obj.method<Il2Cpp.Object>("get_profile").invoke();
      const settings = profile.field("settings").value as Il2Cpp.Object;
      for (
        let index = 0;
        index < settings.method<number>("get_Count").invoke();
        index++
      ) {
        Logger.logNormal(
          settings.method<Il2Cpp.Object>("get_Item").invoke(index).toString() +
            " has existed.",
          "[Il2CppHook]>[PPHook]",
        );
      }

      function addSettings(name: string): Il2Cpp.Object {
        if (
          profile
            .method<Il2Cpp.Object>("HasSettings")
            .inflate(Postprocessing.class(name))
            .invoke()
        ) {
          return profile
            .method<Il2Cpp.Object>("GetSetting")
            .inflate(Postprocessing.class(name))
            .invoke();
        } else {
          return profile
            .method<Il2Cpp.Object>("AddSettings")
            .inflate(Postprocessing.class(name))
            .invoke();
        }
      }

      const bloom = addSettings(
        "UnityEngine.Rendering.PostProcessing.HGMobileBloom",
      );
      (bloom.field("intensity").value as Il2Cpp.Object)
        .method("Override")
        .invoke(5);
      (bloom.field("threshold").value as Il2Cpp.Object)
        .method("Override")
        .invoke(0.6);
      /*let ca = addSettings('UnityEngine.Rendering.PostProcessing.AmbientOcclusion');
      (ca.field('mode').value as Il2Cpp.Object).method('Override')
          .invoke(Postprocessing.class('UnityEngine.Rendering.PostProcessing.AmbientOcclusionMode').field('MultiScaleVolumetricObscurance').value);
      (ca.field('intensity').value as Il2Cpp.Object).method('Override').invoke(4);*/
    }
  }

  function LoginHook(): void {
    let BiliUid = "-1",
      HGUid = "-1";

    // SDKLoginCB
    let SDKLoginCB: Il2Cpp.Method | null = null;
    const LoginViewController = AssemblyCSharp.class(
      "Torappu.UI.Login.LoginViewController",
    );
    const LoginViewControllerNestedClasses = LoginViewController.nestedClasses;
    for (let i = 0; i < LoginViewControllerNestedClasses.length; i++) {
      const klass = LoginViewControllerNestedClasses[i];
      if (klass.name.includes("<DoSDKLogin>c__AnonStorey")) {
        SDKLoginCB = klass.method("<>m__0");
        break;
      }
    }

    // SDKAuthCB
    let SDKAuthCB: Il2Cpp.Method | null = null;
    const U8ExternalToolsNestedClasses = AssemblyCSharp.class(
      "Torappu.SDK.U8ExternalTools",
    ).nestedClasses;
    for (let i = 0; i < U8ExternalToolsNestedClasses.length; i++) {
      const klass = U8ExternalToolsNestedClasses[i];
      if (klass.name.includes("<SendSDKAuthRequest>c__AnonStorey")) {
        SDKAuthCB = klass.method("<>m__0");
        break;
      }
    }

    const UpdateSDKIdAndLogin = LoginViewController.method(
      "_UpdateSDKIdAndLogin",
    );
    const LoginServiceSuccess = LoginViewController.method(
      "_LoginServiceSuccess",
    );

    const Networker = AssemblyCSharp.class("Torappu.Network.Networker");
    const PostWithProperNetworkUtil = Networker.method(
      "_PostWithProperNetworkUtil",
    );

    // hook
    Interceptor.attach(
      Il2CppUtil.getFunctionByAddress(
        Il2Cpp.module,
        PostWithProperNetworkUtil.relativeVirtualAddress,
      ),
      {
        onEnter: (args) => {
          const url = new Il2Cpp.String(args[1]).content as string;
          Logger.logNormal(`Post Url: [1;36m${url}[m`, "[NetworkHook]");
          if (
            HGUid != "-1" &&
            !url.includes("as.hypergryph.com") &&
            !url.includes("/account/login")
          ) {
            accountData["Game"][HGUid]["seqnum"] =
              Networker.method<Il2Cpp.Object>("get_instance")
                .invoke()
                .field<number>("m_seqNum").value + 1;
            saveAccountData();
          }
        },
      },
    );

    if (SDKLoginCB)
      SDKLoginCB.implementation = function (response: Il2Cpp.String) {
        const extension = JSON.parse(response.content as string);
        BiliUid = extension["uid"];
        readAccountData();
        if (BiliUid in accountData["Channel"]) {
          accountData["Channel"][BiliUid]["accessToken"] =
            extension["access_token"];
        } else {
          accountData["Channel"][BiliUid] = {
            accessToken: extension["access_token"],
            gameUid: "-1",
          };
        }
        saveAccountData();
        this.method(SDKLoginCB?.name as string).invoke(response);
      };

    if (SDKAuthCB)
      SDKAuthCB.implementation = function (response: Il2Cpp.Object) {
        const code = response.field<number>("responseCode").value;
        Logger.logNormal(`SDK Login with status ${code}.`, "[LoginHook]");
        readAccountData();
        if (
          code == 400 &&
          accountData["Channel"][BiliUid]["gameUid"] != "-1" &&
          accountData["Channel"][BiliUid]["gameUid"] in accountData["Game"]
        ) {
          HGUid = accountData["Channel"][BiliUid]["gameUid"];
          response.field("responseCode").value = 200;
          response.field("text").value = Il2Cpp.String.from(
            `{"result":0,"error":"","uid":"${HGUid}","channelUid":${BiliUid},"token":"token","isGuest":0,"extension":"{\\"nickName\\":\\"doctor\\"}"}`,
          );
          response.field("isError").value = false;
          response.field("error").value = ptr(0);
        } else if (!response.field<boolean>("isError").value) {
          const resBody = JSON.parse(
            response.field<Il2Cpp.String>("text").value.content as string,
          );
          BiliUid = resBody["channelUid"].toString();
          HGUid = resBody["uid"];
          accountData["Channel"][BiliUid]["gameUid"] = HGUid;
          saveAccountData();
        }
        this.method(SDKAuthCB?.name as string).invoke(response);
      };

    const LoginResponse = AssemblyCSharp.class("Torappu.LoginResponse");
    UpdateSDKIdAndLogin.implementation = function (
      uid: Il2Cpp.String,
      token: Il2Cpp.String,
    ) {
      readAccountData();
      if (token.content == "token") {
        this.method("_UpdateSDKUID").invoke(uid);
        const resBody = Il2CppUtil.instantiate(LoginResponse);
        resBody.field("result").value = 0;
        resBody.field("uid").value = Il2Cpp.String.from(HGUid);
        resBody.field("secret").value = Il2Cpp.String.from(
          accountData["Game"][HGUid]["secret"],
        );
        resBody.field("serviceLicenseVersion").value = 0;
        const NetworkerInstance =
          Networker.method<Il2Cpp.Object>("get_instance").invoke();
        const seqnum: number = accountData["Game"][HGUid]["seqnum"];
        NetworkerInstance.field("m_seqNum").value = seqnum;
        NetworkerInstance.field("m_latestSucceedSeqNum").value = seqnum;
        NetworkerInstance.field("m_lastSeqNumFailed").value = 0;
        this.method("_LoginServiceSuccess").invoke(resBody);
      } else {
        this.method("_UpdateSDKIdAndLogin").invoke(uid, token);
      }
    };

    LoginServiceSuccess.implementation = function (resBody: Il2Cpp.Object) {
      const uid = resBody.field<Il2Cpp.String>("uid").value.content as string;
      readAccountData();
      if (uid in accountData["Game"]) {
        accountData["Game"][
          resBody.field<Il2Cpp.String>("uid").value.content as string
        ]["secret"] = resBody.field<Il2Cpp.String>("secret").value.content;
      } else {
        accountData["Game"][
          resBody.field<Il2Cpp.String>("uid").value.content as string
        ] = {
          secret: resBody.field<Il2Cpp.String>("secret").value.content,
          seqnum: 0,
        };
      }
      saveAccountData();
      this.method("_LoginServiceSuccess").invoke(resBody);
    };
  }

  /**修改概率*/
  function RandomHook(enable: boolean): void {
    AssemblyCSharp.class("Torappu.RandomExtensions").method<boolean>(
      "Dice",
    ).implementation = function (prod) {
      if (enable) {
        return true;
      } else {
        return this.method<boolean>("Dice").invoke(prod);
      }
    };
  }

  enum EnemyHudState {
    TranIn,
    On,
    TranOut,
    Off,
  }

  namespace EnemyHUD {
    let EnemyHud_Enemy: Il2Cpp.Object;
    let EnemyHud_Group: Il2Cpp.Object;
    let EnemyHud_Obj: Il2Cpp.Object;
    let EnemyHud_Name: Il2Cpp.Object;
    let EnemyHud_ID: Il2Cpp.Object;
    let EnemyHud_Des: Il2Cpp.Object;
    let EnemyHud_Blackboard: Il2Cpp.Object;
    let EnemyHud_Blackboard2: Il2Cpp.Object;
    let EnemyHud_LastTime = new Date().getTime();
    const EnemyHud_TransTime = 300;
    const EnemyHud_ShowTime = 3000;
    const EnemyHud_Alpha = 1;
    let EnemyHud_State = EnemyHudState.Off;

    export function ShowEnemyRoute(enemy: Il2Cpp.Object) {
      const cursor = enemy.method<Il2Cpp.Object>("get_cursor").invoke();
      const route = cursor.method<Il2Cpp.Object>("get_route").invoke();
      const motionMode = (route.field("m_data").value as Il2Cpp.Object).field(
        "motionMode",
      ).value;
      const factory =
        BattleControllerInstance?.method<Il2Cpp.Object>("get_factory").invoke();
      const scheduler =
        BattleControllerInstance?.method<Il2Cpp.Object>(
          "get_scheduler",
        ).invoke();
      const previewCursor = factory
        ?.method<Il2Cpp.Object>("CreatePreviewCursor")
        .invoke(motionMode);
      const snapshot = scheduler
        ?.method<Il2Cpp.ValueType>("TakeSnapshot")
        .invoke();
      previewCursor
        ?.method("Spawn")
        .invoke(route, snapshot as Il2Cpp.ValueType, ptr(0));
    }

    export function CreateEnemyHud(UIController: Il2Cpp.Object) {
      EnemyHud_Obj = Il2CppUtil.instantiate(
        GameObject,
        Il2Cpp.String.from("EnemyInfoPanel(Clone)"),
      );
      EnemyHud_Obj.method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method("SetParent")
        .invoke(UIController.method<Il2Cpp.Object>("get_groupStatic").invoke());
      const EnemyHud_Panel = EnemyHud_Obj.method<Il2Cpp.Object>(
        "AddComponent",
      ).invoke(UnityEngineUI.class("UnityEngine.UI.Image").type.object);
      EnemyHud_Group = EnemyHud_Obj.method<Il2Cpp.Object>(
        "AddComponent",
      ).invoke(
        UnityEngineUIModule.class("UnityEngine.CanvasGroup").type.object,
      );
      const rect = EnemyHud_Obj.method<Il2Cpp.Object>("GetComponent").invoke(
        UnityEngineCoreModule.class("UnityEngine.RectTransform").type.object,
      );
      rect
        .method("set_localScale")
        .invoke(Vector3.method<Il2Cpp.ValueType>("get_one").invoke());
      rect
        .method("set_anchorMin")
        .invoke(Vector2.method<Il2Cpp.ValueType>("get_one").invoke());
      rect
        .method("set_anchorMax")
        .invoke(Vector2.method<Il2Cpp.ValueType>("get_one").invoke());
      rect
        .method("set_anchoredPosition3D")
        .invoke(Il2CppUtil.instantiate(Vector3, -280, -300, 0).unbox());
      rect
        .method("set_sizeDelta")
        .invoke(Il2CppUtil.instantiate(Vector2, 720, 250).unbox());
      EnemyHud_Panel.method("set_color").invoke(
        Il2CppUtil.instantiateOverload(
          Color,
          ["System.Single", "System.Single", "System.Single", "System.Single"],
          0,
          0,
          0,
          0.6,
        ).unbox(),
      );
      EnemyHud_Group.method("set_blocksRaycasts").invoke(false);
      EnemyHud_Group.method("set_alpha").invoke(0);

      const EnemyHud_Image_obj: Il2Cpp.Object = Il2CppUtil.instantiate(
        UnityEngineCoreModule.class("UnityEngine.GameObject"),
        Il2Cpp.String.from("EnemyImage"),
      );
      EnemyHud_Image_obj.method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method("SetParent")
        .invoke(EnemyHud_Obj.method<Il2Cpp.Object>("get_transform").invoke());
      const EnemyHud_Image = EnemyHud_Image_obj.method<Il2Cpp.Object>(
        "AddComponent",
      ).invoke(UnityEngineUI.class("UnityEngine.UI.Image").type.object);
      const EnemyHud_Image_rect = EnemyHud_Image_obj.method<Il2Cpp.Object>(
        "GetComponent",
      ).invoke(
        UnityEngineCoreModule.class("UnityEngine.RectTransform").type.object,
      );
      EnemyHud_Image_rect.method("set_localScale").invoke(
        Vector3.method<Il2Cpp.ValueType>("get_one").invoke(),
      );
      EnemyHud_Image_rect.method("set_anchoredPosition3D").invoke(
        Il2CppUtil.instantiate(Vector3, -55, 0, 0).unbox(),
      );
      EnemyHud_Image_rect.method("set_sizeDelta").invoke(
        Il2CppUtil.instantiate(Vector2, 1, 250).unbox(),
      );
      EnemyHud_Image.method("set_color").invoke(
        Il2CppUtil.instantiateOverload(
          Color,
          ["System.Single", "System.Single", "System.Single", "System.Single"],
          0,
          0,
          0,
          0.5,
        ).unbox(),
      );

      const EnemyHud_Name_obj: Il2Cpp.Object = Il2CppUtil.instantiate(
        UnityEngineCoreModule.class("UnityEngine.GameObject"),
        Il2Cpp.String.from("EnemyName"),
      );
      EnemyHud_Name_obj.method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method("SetParent")
        .invoke(EnemyHud_Obj.method<Il2Cpp.Object>("get_transform").invoke());
      EnemyHud_Name = EnemyHud_Name_obj.method<Il2Cpp.Object>(
        "AddComponent",
      ).invoke(UnityEngineUI.class("UnityEngine.UI.Text").type.object);
      const EnemyHud_Name_rect = EnemyHud_Name_obj.method<Il2Cpp.Object>(
        "GetComponent",
      ).invoke(
        UnityEngineCoreModule.class("UnityEngine.RectTransform").type.object,
      );
      EnemyHud_Name_rect.method("set_localScale").invoke(
        Vector3.method<Il2Cpp.ValueType>("get_one").invoke(),
      );
      EnemyHud_Name_rect.method("set_anchoredPosition3D").invoke(
        Il2CppUtil.instantiate(Vector3, 95, 90, 0).unbox(),
      );
      EnemyHud_Name_rect.method("set_sizeDelta").invoke(
        Il2CppUtil.instantiate(Vector2, 260, 45).unbox(),
      );
      EnemyHud_Name.method("set_font").invoke(globalFont);
      EnemyHud_Name.method("set_fontSize").invoke(36);
      EnemyHud_Name.method("set_text").invoke(Il2Cpp.String.from("敌人名字"));
      EnemyHud_Name.field("m_Color").value = Il2CppUtil.instantiateOverload(
        Color,
        ["System.Single", "System.Single", "System.Single", "System.Single"],
        0.8,
        0.2,
        0,
        1,
      ).unbox();

      const EnemyHud_ID_obj: Il2Cpp.Object = Il2CppUtil.instantiate(
        UnityEngineCoreModule.class("UnityEngine.GameObject"),
        Il2Cpp.String.from("EnemyID"),
      );
      EnemyHud_ID_obj.method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method("SetParent")
        .invoke(EnemyHud_Obj.method<Il2Cpp.Object>("get_transform").invoke());
      EnemyHud_ID = EnemyHud_ID_obj.method<Il2Cpp.Object>(
        "AddComponent",
      ).invoke(UnityEngineUI.class("UnityEngine.UI.Text").type.object);
      const EnemyHud_ID_rect = EnemyHud_ID_obj.method<Il2Cpp.Object>(
        "GetComponent",
      ).invoke(
        UnityEngineCoreModule.class("UnityEngine.RectTransform").type.object,
      );
      EnemyHud_ID_rect.method("set_localScale").invoke(
        Vector3.method<Il2Cpp.ValueType>("get_one").invoke(),
      );
      EnemyHud_ID_rect.method("set_anchoredPosition3D").invoke(
        Il2CppUtil.instantiate(Vector3, 95, 60, 0).unbox(),
      );
      EnemyHud_ID_rect.method("set_sizeDelta").invoke(
        Il2CppUtil.instantiate(Vector2, 260, 20).unbox(),
      );
      EnemyHud_ID.method("set_font").invoke(globalFont);
      EnemyHud_ID.method("set_fontSize").invoke(16);
      EnemyHud_ID.method("set_text").invoke(
        Il2Cpp.String.from("enemy_1xxx_xxxxx_2"),
      );
      EnemyHud_ID.field("m_Color").value = Il2CppUtil.instantiateOverload(
        Color,
        ["System.Single", "System.Single", "System.Single", "System.Single"],
        0.2,
        0.2,
        0.2,
        1,
      ).unbox();

      const EnemyHud_Des_obj: Il2Cpp.Object = Il2CppUtil.instantiate(
        UnityEngineCoreModule.class("UnityEngine.GameObject"),
        Il2Cpp.String.from("EnemyDes"),
      );
      EnemyHud_Des_obj.method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method("SetParent")
        .invoke(EnemyHud_Obj.method<Il2Cpp.Object>("get_transform").invoke());
      EnemyHud_Des = EnemyHud_Des_obj.method<Il2Cpp.Object>(
        "AddComponent",
      ).invoke(UnityEngineUI.class("UnityEngine.UI.Text").type.object);
      const EnemyHud_Des_rect = EnemyHud_Des_obj.method<Il2Cpp.Object>(
        "GetComponent",
      ).invoke(
        UnityEngineCoreModule.class("UnityEngine.RectTransform").type.object,
      );
      EnemyHud_Des_rect.method("set_localScale").invoke(
        Vector3.method<Il2Cpp.ValueType>("get_one").invoke(),
      );
      EnemyHud_Des_rect.method("set_anchoredPosition3D").invoke(
        Il2CppUtil.instantiate(Vector3, 120, -30, 0).unbox(),
      );
      EnemyHud_Des_rect.method("set_sizeDelta").invoke(
        Il2CppUtil.instantiate(Vector2, 310, 130).unbox(),
      );
      EnemyHud_Des.method("set_font").invoke(globalFont);
      EnemyHud_Des.method("set_fontSize").invoke(16);
      EnemyHud_Des.method("set_text").invoke(Il2Cpp.String.from("敌人描述"));
      EnemyHud_Des.field("m_Color").value = Il2CppUtil.instantiateOverload(
        Color,
        ["System.Single", "System.Single", "System.Single", "System.Single"],
        1,
        1,
        1,
        1,
      ).unbox();

      const EnemyHud_Blackboard_obj: Il2Cpp.Object = Il2CppUtil.instantiate(
        UnityEngineCoreModule.class("UnityEngine.GameObject"),
        Il2Cpp.String.from("EnemyBlackboard"),
      );
      EnemyHud_Blackboard_obj.method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method("SetParent")
        .invoke(EnemyHud_Obj.method<Il2Cpp.Object>("get_transform").invoke());
      EnemyHud_Blackboard = EnemyHud_Blackboard_obj.method<Il2Cpp.Object>(
        "AddComponent",
      ).invoke(UnityEngineUI.class("UnityEngine.UI.Text").type.object);
      const EnemyHud_Blackboard_rect =
        EnemyHud_Blackboard_obj.method<Il2Cpp.Object>("GetComponent").invoke(
          UnityEngineCoreModule.class("UnityEngine.RectTransform").type.object,
        );
      EnemyHud_Blackboard_rect.method("set_localScale").invoke(
        Vector3.method<Il2Cpp.ValueType>("get_one").invoke(),
      );
      EnemyHud_Blackboard_rect.method("set_anchoredPosition3D").invoke(
        Il2CppUtil.instantiate(Vector3, -220, 0, 0).unbox(),
      );
      EnemyHud_Blackboard_rect.method("set_sizeDelta").invoke(
        Il2CppUtil.instantiate(Vector2, 230, 220).unbox(),
      );
      EnemyHud_Blackboard.method("set_font").invoke(globalFont);
      EnemyHud_Blackboard.method("set_fontSize").invoke(18);
      EnemyHud_Blackboard.method("set_text").invoke(
        Il2Cpp.String.from(
          `攻击 <color=#D63A00>6756</color>
防御 <color=#D63A00>233</color>
法抗 <color=#D63A00>222</color>
阻挡 <color=#66CCFF>222</color>
消耗目标数量 <color=#66CCFF>2</color>
阻挡干员 <color=#00B035>干员名字</color>
当前目标 <color=#66CCFF>单位名字</color>
坐标 <color=#66CCFF>(2.342,4.211)</color>`,
        ),
      );
      EnemyHud_Blackboard.field("m_Color").value =
        Il2CppUtil.instantiateOverload(
          Color,
          ["System.Single", "System.Single", "System.Single", "System.Single"],
          1,
          1,
          1,
          1,
        ).unbox();

      const EnemyHud_Blackboard2_obj: Il2Cpp.Object = Il2CppUtil.instantiate(
        UnityEngineCoreModule.class("UnityEngine.GameObject"),
        Il2Cpp.String.from("EnemyBlackboard2"),
      );
      EnemyHud_Blackboard2_obj.method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method("SetParent")
        .invoke(EnemyHud_Obj.method<Il2Cpp.Object>("get_transform").invoke());
      EnemyHud_Blackboard2 = EnemyHud_Blackboard2_obj.method<Il2Cpp.Object>(
        "AddComponent",
      ).invoke(UnityEngineUI.class("UnityEngine.UI.Text").type.object);
      const EnemyHud_Blackboard2_rect =
        EnemyHud_Blackboard2_obj.method<Il2Cpp.Object>("GetComponent").invoke(
          UnityEngineCoreModule.class("UnityEngine.RectTransform").type.object,
        );
      EnemyHud_Blackboard2_rect.method("set_localScale").invoke(
        Vector3.method<Il2Cpp.ValueType>("get_one").invoke(),
      );
      EnemyHud_Blackboard2_rect.method("set_anchoredPosition3D").invoke(
        Il2CppUtil.instantiate(Vector3, -120, 0, 0).unbox(),
      );
      EnemyHud_Blackboard2_rect.method("set_sizeDelta").invoke(
        Il2CppUtil.instantiate(Vector2, 120, 220).unbox(),
      );
      EnemyHud_Blackboard2.method("set_font").invoke(globalFont);
      EnemyHud_Blackboard2.method("set_fontSize").invoke(18);
      EnemyHud_Blackboard2.method("set_text").invoke(
        Il2Cpp.String.from(
          `移速 <color=#66CCFF>3.0</color>
攻速 <color=#66CCFF>222</color>
重量 <color=#66CCFF>7</color>
失衡免疫 <color=#66CCFF>是</color>`,
        ),
      );
      EnemyHud_Blackboard2.field("m_Color").value =
        Il2CppUtil.instantiateOverload(
          Color,
          ["System.Single", "System.Single", "System.Single", "System.Single"],
          1,
          1,
          1,
          1,
        ).unbox();

      EnemyHud_Obj.method("SetActive").invoke(false);
      EnemyHud_State = EnemyHudState.Off;
    }

    export function UpdateEnemyHudData() {
      if (
        EnemyHud_Enemy.isNull() ||
        !EnemyHud_Enemy.method<boolean>("get_alive").invoke()
      ) {
        EnemyHud_Blackboard.method("set_text").invoke(
          Il2Cpp.String.from("敌人已死亡"),
        );
        EnemyHud_Blackboard2.method("set_text").invoke(ptr(0));
      } else {
        const ability = EnemyHud_Enemy.method<Il2Cpp.Object>(
          "get_attackAbilityCasted",
        ).invoke();
        let abname = "无";
        let targetNames = "无";
        if (!ability.isNull()) {
          abname = ability.method<Il2Cpp.String>("get_searchName").invoke()
            .content as string;
          const targets = ability
            .method<Il2Cpp.Object>("get_castTargets")
            .invoke();
          const targetArray = targets
            .method<Il2Cpp.Array<Il2Cpp.ValueType>>("ToArray")
            .invoke();
          if (targetArray.length > 0) {
            const tsn = Array<string>(targetArray.length);
            for (let index = 0; index < targetArray.length; index++) {
              const obj = targetArray.get(index).field("obj")
                .value as Il2Cpp.Object;
              if (
                AssemblyCSharp.class("Torappu.Battle.Character")
                  .type.object.method<boolean>("IsAssignableFrom")
                  .invoke(obj.class.type.object)
              ) {
                tsn[index] = CharacterUtil.method<Il2Cpp.String>(
                  "GetCharName",
                ).invoke(obj.method<Il2Cpp.String>("get_characterId").invoke())
                  .content as string;
              } else {
                tsn[index] = obj.method<Il2Cpp.String>("get_id").invoke()
                  .content as string;
              }
            }
            targetNames = tsn.join("  ");
          }
        }
        const pos = UnityUtil.vector2ToTuple(
          EnemyHud_Enemy.method<Il2Cpp.ValueType>(
            "get_footMapPosition",
          ).invoke(),
        );
        const blocker =
          EnemyHud_Enemy.method<Il2Cpp.Object>("get_blocker").invoke();
        EnemyHud_Blackboard.method("set_text").invoke(
          Il2Cpp.String.from(
            `攻击 <color=#D63A00>${EnemyHud_Enemy.method<Il2Cpp.ValueType>("get_atk").invoke().box().method<number>("AsFloat").invoke().toFixed(2)}</color>
防御 <color=#D63A00>${EnemyHud_Enemy.method<Il2Cpp.ValueType>("get_def").invoke().box().method<number>("AsFloat").invoke().toFixed(2)}</color>
法抗 <color=#D63A00>${EnemyHud_Enemy.method<Il2Cpp.ValueType>("get_magicResistance").invoke().box().method<number>("AsFloat").invoke().toFixed(2)}</color>
阻挡 <color=#66CCFF>${EnemyHud_Enemy.method<number>("get_blockVolume").invoke()}</color>
剩余距离 <color=#66CCFF>${EnemyHud_Enemy.method<number>("get_distToExit").invoke().toFixed(3)}</color>
阻挡干员 <color=#00B035>${blocker.isNull() ? "无阻挡" : CharacterUtil.method<Il2Cpp.String>("GetCharName").invoke(blocker.method<Il2Cpp.String>("get_characterId").invoke()).content}</color>
坐标 <color=#66CCFF>(${pos[0].toFixed(2)}, ${pos[1].toFixed(2)})</color>
当前技能 <color=#FF4000>${abname}</color>
技能目标 <color=#FF4000>${targetNames}</color>`,
          ),
        );
        EnemyHud_Blackboard2.method("set_text").invoke(
          Il2Cpp.String.from(
            `移速 <color=#66CCFF>${EnemyHud_Enemy.method<number>("get_moveSpeed").invoke().toFixed(3)}</color>
攻速 <color=#66CCFF>${((EnemyHud_Enemy.method<Il2Cpp.ValueType>("get_baseAttackTime").invoke().box().method<number>("AsFloat").invoke() * 100) / EnemyHud_Enemy.method<Il2Cpp.ValueType>("get_attackSpeed").invoke().box().method<number>("AsFloat").invoke()).toFixed(3)}</color>
重量 <color=#66CCFF>${EnemyHud_Enemy.method<number>("get_massLevel").invoke()}</color>
目标点 <color=#66CCFF>${EnemyHud_Enemy.method<number>("get_lifePointReduce").invoke()}</color>`,
          ),
        );
      }
    }

    export function UpdateEnemyHud() {
      const t = new Date().getTime();
      switch (EnemyHud_State) {
        case EnemyHudState.TranIn:
          if (t - EnemyHud_LastTime >= EnemyHud_TransTime) {
            EnemyHud_State = EnemyHudState.On;
            EnemyHud_Group.method("set_alpha").invoke(EnemyHud_Alpha);
          } else {
            EnemyHud_Group.method("set_alpha").invoke(
              (EnemyHud_Alpha * (t - EnemyHud_LastTime)) / EnemyHud_TransTime,
            );
          }
          UpdateEnemyHudData();
          break;
        case EnemyHudState.On:
          if (t - EnemyHud_LastTime >= EnemyHud_ShowTime) {
            EnemyHud_State = EnemyHudState.TranOut;
            EnemyHud_LastTime = new Date().getTime();
          }
          UpdateEnemyHudData();
          break;
        case EnemyHudState.TranOut:
          if (t - EnemyHud_LastTime >= EnemyHud_TransTime) {
            EnemyHud_State = EnemyHudState.Off;
            EnemyHud_Group.method("set_alpha").invoke(0);
            EnemyHud_Obj.method("SetActive").invoke(false);
          } else {
            EnemyHud_Group.method("set_alpha").invoke(
              EnemyHud_Alpha *
                (1 - (t - EnemyHud_LastTime) / EnemyHud_TransTime),
            );
          }
          UpdateEnemyHudData();
          break;
      }
    }

    export function SetEnemyHud(enemy: Il2Cpp.Object) {
      OnUIEntrance();
      if (
        EnemyHud_Enemy != undefined &&
        !EnemyHud_Enemy.isNull() &&
        enemy.method<number>("get_instanceUid").invoke() !=
          EnemyHud_Enemy.method<number>("get_instanceUid").invoke()
      ) {
        hasPlay = false;
      }
      EnemyHud_Enemy = enemy;
      const edata = enemy.method<Il2Cpp.Object>("get_data").invoke();
      const eid = edata.field("key").value as Il2Cpp.String;
      EnemyHud_ID.method("set_text").invoke(eid);
      EnemyHud_Name.method("set_text").invoke(edata.field("name").value);
      EnemyHud_Des.method("set_text").invoke(
        FormatUtil.method<Il2Cpp.String>("FormatRichTextFromData").invoke(
          edata.field("description").value,
        ),
      );
      if (EnemyHud_State == EnemyHudState.Off) {
        EnemyHud_State = EnemyHudState.TranIn;
        EnemyHud_LastTime = new Date().getTime();
        EnemyHud_Obj.method("SetActive").invoke(true);
        //log('Off -> In')
      } else if (EnemyHud_State == EnemyHudState.TranOut) {
        EnemyHud_State = EnemyHudState.TranIn;
        const t = new Date().getTime();
        EnemyHud_LastTime = 2 * t - EnemyHud_TransTime - EnemyHud_LastTime;
        //log('TranOut -> In')
      } else if (EnemyHud_State == EnemyHudState.On) {
        EnemyHud_LastTime = new Date().getTime();
      }
      if (!hasPlay) {
        ShowEnemyRoute(enemy);
        hasPlay = true;
      }
    }

    let EnemyHud_Enemy_Color = false,
      EnemyHud_Enemy_FingerId: number = -1;

    export function UpdateEnemyClick(scheduler: Il2Cpp.Object) {
      if (Input.method<number>("get_touchCount").invoke() > 0) {
        const t = Input.method<Il2Cpp.ValueType>("GetTouch").invoke(0);

        if (
          t.field("m_Phase").value.toString() == "Began" &&
          GetKey.invoke(VISABLE)
        ) {
          const pos = UnityUtil.vector2ToTuple(
            t.field("m_Position").value as Il2Cpp.ValueType,
          );
          const ray = Camera.method<Il2Cpp.Object>("get_main")
            .invoke()
            .method<Il2Cpp.ValueType>("ScreenPointToRay")
            .invoke(Il2CppUtil.instantiate(Vector3, pos[0], pos[1], 0).unbox())
            .box();
          const origin = UnityUtil.vector3ToTuple(
            ray.method<Il2Cpp.ValueType>("get_origin").invoke(),
          );
          const direction = UnityUtil.vector3ToTuple(
            ray.method<Il2Cpp.ValueType>("get_direction").invoke(),
          );

          function culDis(x: number, y: number, z: number): number {
            const n = (z - origin[2]) / direction[2];
            return (
              (origin[0] + direction[0] * n - x) ** 2 +
              (origin[1] + direction[1] * n - y) ** 2
            );
          }

          const enemies = scheduler.field("m_managedFinalEnemies")
            .value as Il2Cpp.Object;
          const minDis = Number.MAX_VALUE;
          let curEnemy: Il2Cpp.Object | null = null;
          for (
            let index = 0;
            index < enemies.method<number>("get_Count").invoke();
            index++
          ) {
            const enemy = enemies
              .method<Il2Cpp.Object>("get_Item")
              .invoke(index);
            const pos = UnityUtil.vector3ToTuple(
              enemy
                .method<Il2Cpp.Object>("get_transform")
                .invoke()
                .method<Il2Cpp.ValueType>("get_position")
                .invoke(),
            );
            const dis = culDis(pos[0], pos[1], pos[2]);
            if (dis < 0.25 && dis < minDis) {
              curEnemy = enemy;
            }
          }
          if (curEnemy != null) {
            EnemyHud_Enemy_FingerId = t.field("m_FingerId").value as number;
            if (EnemyHud_Enemy_Color) {
              if (!EnemyHud_Enemy.isNull()) {
                EnemyHud_Enemy.method("set_color").invoke(
                  EnemyHud_Enemy.method<Il2Cpp.ValueType>(
                    "get_defaultBodyColor",
                  ).invoke(),
                );
                EnemyHud_Enemy_Color = false;
              }
            }
            SetEnemyHud(curEnemy);
            EnemyHud_Enemy.method("set_color").invoke(
              Il2CppUtil.instantiateOverload(
                Color,
                [
                  "System.Single",
                  "System.Single",
                  "System.Single",
                  "System.Single",
                ],
                0,
                1,
                1,
                1,
              ).unbox(),
            );
            EnemyHud_Enemy_Color = true;
          }
        } else if (
          (t.field("m_Phase").value.toString() == "Stationary" ||
            t.field("m_Phase").value.toString() == "Moved") &&
          (t.field("m_FingerId").value as number) == EnemyHud_Enemy_FingerId &&
          !EnemyHud_Enemy.isNull()
        ) {
          if (EnemyHud_State == EnemyHudState.Off) {
            EnemyHud_State = EnemyHudState.TranIn;
            EnemyHud_LastTime = new Date().getTime();
          } else if (EnemyHud_State == EnemyHudState.TranOut) {
            EnemyHud_State = EnemyHudState.TranIn;
            const t = new Date().getTime();
            EnemyHud_LastTime = 2 * t - EnemyHud_TransTime - EnemyHud_LastTime;
          } else if (EnemyHud_State == EnemyHudState.On) {
            EnemyHud_LastTime = new Date().getTime();
          }
          EnemyHud_Enemy.method("set_color").invoke(
            Il2CppUtil.instantiateOverload(
              Color,
              [
                "System.Single",
                "System.Single",
                "System.Single",
                "System.Single",
              ],
              0,
              1,
              1,
              1,
            ).unbox(),
          );
          EnemyHud_Enemy_Color = true;
        } else if (EnemyHud_Enemy_Color) {
          if (!EnemyHud_Enemy.isNull()) {
            EnemyHud_Enemy.method("set_color").invoke(
              EnemyHud_Enemy.method<Il2Cpp.ValueType>(
                "get_defaultBodyColor",
              ).invoke(),
            );
            EnemyHud_Enemy_Color = false;
            EnemyHud_Enemy_FingerId = -1;
          }
        }
      }
    }
  }

  function TASHook(): void {
    if (!SETTING.EnableTAS) return;

    enum State {
      Ctor,
      Playing,
      NotPlaying,
    }

    enum TasMode {
      Normal, // 正常 - c
      SingleFrame, // 单帧 - 1
      DoubleFrame, // 双帧 - 2
      PlayingOnDown, // 按下时 - r
      PlayingOnUp, // 抬起时 - f
    }

    let state = State.NotPlaying;
    let tasMode = TasMode.Normal;

    const Torappu_Battle_BattleController = AssemblyCSharp.class(
      "Torappu.Battle.BattleController",
    );
    const Torappu_Battle_UI_UIController = AssemblyCSharp.class(
      "Torappu.Battle.UI.UIController",
    );

    const get_fixedPlayTime =
      Torappu_Battle_BattleController.method<Il2Cpp.ValueType>(
        "get_fixedPlayTime",
      );
    const get_fixedFrameCnt =
      Torappu_Battle_BattleController.method<number>("get_fixedFrameCnt");
    const BattleControllerCtor =
      Torappu_Battle_BattleController.method("Awake");
    const UIControllerCtor = Torappu_Battle_UI_UIController.method("Awake");

    let get_isPaused: Il2Cpp.Method<boolean>,
      get_isPlaying: Il2Cpp.Method<boolean>,
      SetPaused: Il2Cpp.Method<Il2Cpp.Method.ReturnType>,
      set_speedLevel: Il2Cpp.Method,
      set_timeScale: Il2Cpp.Method,
      OnSpeedLevelChanged: Il2Cpp.Method;
    Interceptor.attach(
      Il2CppUtil.getFunctionByAddress(
        Il2Cpp.module,
        BattleControllerCtor.relativeVirtualAddress,
      ),
      {
        onEnter: (args) => {
          BattleControllerInstance = new Il2Cpp.Object(args[0]);
          set_speedLevel = BattleControllerInstance.method("set_speedLevel");
          set_timeScale = BattleControllerInstance.method("set_timeScale");
          get_isPlaying =
            BattleControllerInstance.method<boolean>("get_isPlaying");
          OnSpeedLevelChanged = BattleControllerInstance.method(
            "_OnSpeedLevelChanged",
          );
          /*BattleControllerInstance.method('OnEnemyReachedExit').implementation = function (enemy) {
            log("Enemy exit.");
        };*/
        },
      },
    );

    let set_time_text: Il2Cpp.Method | null = null,
      set_frameCount_text: Il2Cpp.Method | null = null;
    Interceptor.attach(
      Il2CppUtil.getFunctionByAddress(
        Il2Cpp.module,
        UIControllerCtor.relativeVirtualAddress,
      ),
      {
        onEnter: (args) => {
          UIControllerInstance = new Il2Cpp.Object(args[0]);
          get_isPaused = UIControllerInstance.method<boolean>("get_isPaused");
          SetPaused = UIControllerInstance.method("SetPaused");
          state = State.Ctor;
          if (SETTING["PP"]) PPHook();
          EnemyHUD.CreateEnemyHud(UIControllerInstance);
          if (SETTING["ShowBattleTimeInfo"]) {
            const shower = Il2CppUtil.instantiate(
              UnityEngineCoreModule.class("UnityEngine.GameObject"),
              Il2Cpp.String.from("TimeShower (Clone)"),
            );
            const groupStatic =
              UIControllerInstance.method<Il2Cpp.Object>(
                "get_groupStatic",
              ).invoke();
            shower
              .method<Il2Cpp.Object>("get_transform")
              .invoke()
              .method("SetParent")
              .invoke(groupStatic);
            const text = shower
              .method<Il2Cpp.Object>("AddComponent")
              .invoke(UnityEngineUI.class("UnityEngine.UI.Text").type.object);
            const rect = shower
              .method<Il2Cpp.Object>("GetComponent")
              .invoke(
                UnityEngineCoreModule.class("UnityEngine.RectTransform").type
                  .object,
              );
            rect
              .method("set_anchoredPosition3D")
              .invoke(Il2CppUtil.instantiate(Vector3, -550, 480, 0).unbox());
            rect
              .method("set_localScale")
              .invoke(Vector3.method<Il2Cpp.ValueType>("get_one").invoke());
            rect
              .method("set_sizeDelta")
              .invoke(Il2CppUtil.instantiate(Vector2, 400, 50).unbox());
            //let font = UnityEngineCoreModule.class('UnityEngine.Resources').method<Il2Cpp.Object>('GetBuiltinResource').invoke(Il2Cpp.Domain.assembly('UnityEngine.TextRenderingModule').image.class('UnityEngine.Font').type.object, Il2Cpp.String.from('Arial.ttf'));
            text.method("set_font").invoke(globalFont);
            text.method("set_fontSize").invoke(30);
            set_time_text = text.method("set_text");
            set_time_text.invoke(Il2Cpp.String.from("战斗时间轴: 0.000s"));
            const shower2 = Il2CppUtil.instantiate(
              UnityEngineCoreModule.class("UnityEngine.GameObject"),
              Il2Cpp.String.from("FrameShower (Clone)"),
            );
            shower2
              .method<Il2Cpp.Object>("get_transform")
              .invoke()
              .method("SetParent")
              .invoke(groupStatic);
            const text2 = shower2
              .method<Il2Cpp.Object>("AddComponent")
              .invoke(UnityEngineUI.class("UnityEngine.UI.Text").type.object);
            const rect2 = shower2
              .method<Il2Cpp.Object>("GetComponent")
              .invoke(
                UnityEngineCoreModule.class("UnityEngine.RectTransform").type
                  .object,
              );
            rect2
              .method("set_anchoredPosition3D")
              .invoke(Il2CppUtil.instantiate(Vector3, -550, 430, 0).unbox());
            rect2
              .method("set_localScale")
              .invoke(Vector3.method<Il2Cpp.ValueType>("get_one").invoke());
            rect2
              .method("set_sizeDelta")
              .invoke(Il2CppUtil.instantiate(Vector2, 400, 50).unbox());
            text2.method("set_font").invoke(globalFont);
            text2.method("set_fontSize").invoke(30);
            set_frameCount_text = text2.method("set_text");
            set_frameCount_text.invoke(Il2Cpp.String.from("Tick计数: 0 tick"));
          }
        },
      },
    );

    const OnDestroy = Torappu_Battle_BattleController.method("OnDestroy");
    Interceptor.attach(
      Il2CppUtil.getFunctionByAddress(
        Il2Cpp.module,
        OnDestroy.relativeVirtualAddress,
      ),
      {
        onLeave: (retval) => {
          BattleControllerInstance = null;
          state = State.NotPlaying;
        },
      },
    );

    const StartGame = Torappu_Battle_BattleController.method("StartGame");
    Interceptor.attach(
      Il2CppUtil.getFunctionByAddress(
        Il2Cpp.module,
        StartGame.relativeVirtualAddress,
      ),
      {
        onLeave: (retval) => {
          state = State.Playing;
          switch (tasMode) {
            case TasMode.SingleFrame:
            case TasMode.DoubleFrame:
            case TasMode.PlayingOnDown:
              SetPaused.invoke(true, false, false);
              OnUIClick();
          }
        },
      },
    );

    const SpeedLevel = AssemblyCSharp.class("Torappu.Battle.SpeedLevel");
    const Update = Torappu_Battle_BattleController.method("Update");
    let frameCount = 0;
    Interceptor.attach(
      Il2CppUtil.getFunctionByAddress(
        Il2Cpp.module,
        Update.relativeVirtualAddress,
      ),
      {
        onLeave: (retval) => {
          if (GetKeyDown.invoke(Normal)) {
            tasMode = TasMode.Normal;
            //send('正常模式');
          } else if (GetKeyDown.invoke(SingleFrame)) {
            tasMode = TasMode.SingleFrame;
            SetPaused.invoke(true, false, false);
            OnUIClick();
            //send('SetPaused', [1]);
            //send('单帧模式');
          } else if (GetKeyDown.invoke(DoubleFrame)) {
            tasMode = TasMode.DoubleFrame;
            frameCount = 0;
            SetPaused.invoke(true, false, false);
            OnUIClick();
            //send('SetPaused', [1]);
            //send('双帧模式');
          } else if (GetKeyDown.invoke(PlayingOnDown)) {
            tasMode = TasMode.PlayingOnDown;
            SetPaused.invoke(true, false, false);
            OnUIClick();
            //send('SetPaused', [1]);
            //send('按下时');
          } else if (GetKeyDown.invoke(PlayingOnUp)) {
            tasMode = TasMode.PlayingOnUp;
            SetPaused.invoke(false, false, false);
            //send('SetPaused', [0]);
            //send('抬起时');
          }
          const isRun =
            BattleControllerInstance != null && get_isPlaying.invoke();
          if (isRun) {
            switch (tasMode) {
              case TasMode.SingleFrame:
                if (!get_isPaused.invoke()) {
                  SetPaused.invoke(true, false, false);
                  OnUIClick();
                  //send('SetPaused', [1]);
                }
                break;
              case TasMode.DoubleFrame:
                if (!get_isPaused.invoke()) {
                  if (frameCount > 0) {
                    frameCount = 0;
                    SetPaused.invoke(true, false, false);
                    OnUIClick();
                    //send('SetPaused', [1]);
                  } else {
                    frameCount++;
                  }
                }
                break;
            }
            if (SETTING["ShowBattleTimeInfo"]) {
              set_time_text?.invoke(
                Il2Cpp.String.from(
                  "战斗时间轴: " +
                    get_fixedPlayTime
                      .invoke()
                      .box()
                      .method<number>("AsFloat")
                      .invoke()
                      .toFixed(3)
                      .toString() +
                    "s",
                ),
              );
              set_frameCount_text?.invoke(
                Il2Cpp.String.from(
                  "Tick计数: " +
                    get_fixedFrameCnt.invoke().toString() +
                    " tick",
                ),
              );
            }
            //send('Time', get_fixedPlayTime.invoke().handle.readByteArray(8));
          }
          if (GetKeyDown.invoke(CONTROL) && isRun) {
            switch (tasMode) {
              case TasMode.Normal:
                const s = !get_isPaused.invoke();
                SetPaused.invoke(s, false, false);
                if (s) OnUIClick();
                //send('SetPaused', [s ? 1 : 0]);
                break;
              case TasMode.SingleFrame:
              case TasMode.DoubleFrame:
              case TasMode.PlayingOnDown:
                SetPaused.invoke(false, false, false);
                //send('SetPaused', [0]);
                break;
              case TasMode.PlayingOnUp:
                SetPaused.invoke(true, false, false);
                OnUIClick();
                //send('SetPaused', [1]);
                break;
            }
          }
          if (GetKeyUp.invoke(CONTROL) && isRun) {
            switch (tasMode) {
              case TasMode.PlayingOnDown:
                SetPaused.invoke(true, false, false);
                OnUIClick();
                //send('SetPaused', [1]);
                break;
              case TasMode.PlayingOnUp:
                SetPaused.invoke(false, false, false);
                //send('SetPaused', [0]);
                break;
            }
          }
          if (GetKeyDown.invoke(THREE) && SETTING["SpeedLevel3"]) {
            set_speedLevel.invoke(SpeedLevel.field("SUPER_FAST").value);
          }
          if (GetKeyDown.invoke(FOUR) && SETTING["SpeedLevel16"]) {
            set_timeScale.invoke(16);
            OnSpeedLevelChanged.invoke(SpeedLevel.field("SUPER_FAST").value);
          }
          if (isRun && !get_isPaused.invoke() && hasPlay) {
            hasPlay = false;
          }
          EnemyHUD.UpdateEnemyClick(
            BattleControllerInstance?.method<Il2Cpp.Object>(
              "get_scheduler",
            ).invoke() as Il2Cpp.Object,
          );
          EnemyHUD.UpdateEnemyHud();
        },
      },
    );
  }

  export function main(): void {
    Logger.logNormal("[Il2CppHook] Starting il2cpp layer hook...");
    Logger.log(
      "[1;36m应用包名:[m [1;34m" + Il2Cpp.applicationIdentifier + "[m",
    );
    Logger.log("[1;36m版本:[m [1;34m" + Il2Cpp.applicationVersion + "[m");
    Logger.log("[1;36m路径:[m [1;34m" + Il2Cpp.applicationDataPath + "[m");
    Logger.log("[1;36mUnity版本:[m [1;34m" + Il2Cpp.unityVersion + "[m");
    Logger.log("[1;36mPid:[m [1;34m" + Process.id.toString() + "[m");
    Logger.log("[1;36mAPK签名:[m [1;34m" + JavaUtil.getAppSignature() + "[m");
    tryCallingHook(
      [initHook, initAccountData, NetworkHook, LogHook, MiscHook, TASHook],
      [
        "initHook",
        "initAccountData",
        "NetworkHook",
        "LogHook",
        "MiscHook",
        "TASHook",
      ],
      "[Il2CppHook]",
    );
    Logger.logNormal("[Il2CppHook] Starting UIBaseHook()...");
    UIBaseHook();
  }
}

Logger.log("[1;36m==========Programme started!==========[m");
Logger.l(Buffer.from(title, "base64").toString());
Java.perform(JavaHook.main);
setTimeout(() => Il2Cpp.perform(Il2CppHook.main), SETTING["Il2CppHookDelay"]);
