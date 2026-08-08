// Assembly-CSharp.dll
public class Torappu.PlayerDataModel : System.Object
{
	// Fields
	public Torappu.PlayerStatus status; // 0x20
	public System.Collections.Generic.Dictionary<System.String,Torappu.PlayerMonthlySubPer> monthlySub; // 0x28
	public System.Collections.Generic.Dictionary<System.String,Torappu.ListDict<System.Int32,Torappu.PlayerConsumableItem>> consumable; // 0xa0
	public Torappu.PlayerGacha gacha; // 0xd8
	public System.String nickName; // 0x18
	public System.Int32 level; // 0x48
	// Methods
	public System.String Serialize(); // 0x0
	public System.Void .ctor(); // 0x0
}
// Assembly-CSharp.dll
public class Torappu.PlayerStatus : System.Object, Torappu.IHotfixable
{
	// Fields
	public System.String nickName; // 0x10
	public System.Int32 ap; // 0x28
	public System.Boolean apLimitUpFlag; // 0x88
	public Torappu.PlayerAvatarType avatarType; // 0x90
	// Methods
	public System.Void .ctor(); // 0x0
}
// Assembly-CSharp.dll
public class Torappu.PlayerGacha : System.Object
{
	// Fields
	public Torappu.GachaType lastGachaType; // 0x10
	// Methods
	public System.Void .ctor(); // 0x0
}
// Assembly-CSharp.dll
public class Torappu.PlayerMonthlySubPer : System.Object
{
	// Fields
	public System.String id; // 0x10
	// Methods
}
// Assembly-CSharp.dll
public class Torappu.PlayerConsumableItem : System.Object
{
	// Fields
	public System.Int32 count; // 0x10
	// Methods
}
// Assembly-CSharp.dll
public enum Torappu.PlayerAvatarType : 
{
	// Fields
	public System.Int32 value__; // 0x10
	public const Torappu.PlayerAvatarType NONE = 0; // 0x0
	public const Torappu.PlayerAvatarType ASSISTANT = 1; // 0x0
	// Methods
}
// Assembly-CSharp.dll
public enum Torappu.GachaType : 
{
	// Fields
	public System.Int32 value__; // 0x10
	public const Torappu.GachaType None = 4294967295; // 0x0
	public const Torappu.GachaType Diamond = 0; // 0x0
	public const Torappu.GachaType SingleTicket = 1; // 0x0
	public const Torappu.GachaType TenTicket = 2; // 0x0
	// Methods
}
// Assembly-CSharp.dll
public class Torappu.Tower : System.Object
{
	// Fields
	public System.Int32 x; // 0x10
	// Methods
}
