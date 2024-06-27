package config

var Cfg Config

type Config struct {
	Mode                     string
	ApiListen                string
	DatabaseURL              string
	SecretKey                string
	RedisAddr                string
	RedisPassword            string
	Emails                   []EmailConfig
	UToolAPIKeys             []string
	TwitterAPIKey            string
	TwitterAPIKeySecret      string
	DiscordClientId          string
	DiscordClientSecret      string
	OfficialTwitterUserId    int64
	OfficialTelegramGroupId  int64
	DiscordBotToken          string
	TelegramBotTestToken     string
	TelegramBotSparkToken    string
	TelegramBotID            string
	TelegramCallback         string
	RedirectURI              string
	DisableDiscordBot        bool
	BrowsOfficialWebsiteTime int64  // 浏览官网的时间
	OfficialWebsiteURI       string // 官网地址
	AesKey                   string
	InviteShareRate          int64 // 邀请比例分成

	TitanAPI TitanAPIConfig

	GoogleDoc    GoogleDocConfig
	ResourcePath string
}

type TitanAPIConfig struct {
	BasePath string
	Key      string
}

type EmailConfig struct {
	From     string
	Nickname string
	SMTPHost string
	SMTPPort string
	Username string
	Password string
}

// GoogleDocConfig 谷歌文档配置
type GoogleDocConfig struct {
	EnDocID   string
	CnDocID   string
	EnURI     string
	CnURI     string
	CredPath  string
	TokenPath string
}
