package api

import (
	"image/color"
	"time"

	config2 "github.com/TestsLing/aj-captcha-go/config"
	constant "github.com/TestsLing/aj-captcha-go/const"
	"github.com/TestsLing/aj-captcha-go/service"
	"github.com/bwmarrin/discordgo"
	"github.com/gnasnik/titan-quest/config"
	"github.com/gnasnik/titan-quest/core/bot/discord"

	"github.com/gin-gonic/gin"
	logging "github.com/ipfs/go-log/v2"
	tele "gopkg.in/telebot.v3"
)

var (
	TeleBot *tele.Bot
	DCBot   *discordgo.Session
)

var log = logging.Logger("api")

// 行为校验初始化
var (
	factory *service.CaptchaServiceFactory
)

func InitBot() {
	pref := tele.Settings{
		Token:  config.Cfg.TelegramBotTestToken,
		Poller: &tele.LongPoller{Timeout: 10 * time.Second},
	}

	b, err := tele.NewBot(pref)
	if err != nil {
		log.Errorf("create telegram cmd: %v", err)
		return
	}

	dbot, err := discord.NewBot(config.Cfg.DiscordBotToken)
	if err != nil {
		log.Errorf("create discord bot: %v", err)
	}

	if !config.Cfg.DisableDiscordBot {
		go discord.RunDiscordBot(dbot)
	}

	TeleBot = b
	DCBot = dbot
}

func InitCaptcha() {
	// 水印配置
	clickWordConfig := &config2.ClickWordConfig{
		FontSize: 25,
		FontNum:  4,
	}
	// 点击文字配置
	watermarkConfig := &config2.WatermarkConfig{
		FontSize: 12,
		Color:    color.RGBA{R: 255, G: 255, B: 255, A: 255},
		Text:     "",
	}
	// 滑动模块配置
	blockPuzzleConfig := &config2.BlockPuzzleConfig{Offset: 200}
	configcap := config2.BuildConfig(constant.RedisCacheKey, config.Cfg.ResourcePath, watermarkConfig,
		clickWordConfig, blockPuzzleConfig, 2*60)
	factory = service.NewCaptchaServiceFactory(configcap)
}

func ServerAPI(cfg *config.Config) {
	gin.SetMode(cfg.Mode)
	r := gin.Default()
	// r.Use(Cors())
	r.Use(RequestLoggerMiddleware())

	// 人机校验：滑块验证
	// 行为校验配置模块
	//注册内存缓存
	factory.RegisterCache(constant.RedisCacheKey, service.NewConfigRedisCacheService([]string{config.Cfg.RedisAddr}, "", config.Cfg.RedisPassword, false, 0))
	factory.RegisterService(constant.ClickWordCaptcha, service.NewClickWordCaptchaService(factory))
	factory.RegisterService(constant.BlockPuzzleCaptcha, service.NewBlockPuzzleCaptchaService(factory))

	apiV1 := r.Group("/api/v1")
	authMiddleware, err := jwtGinMiddleware(cfg.SecretKey)
	if err != nil {
		log.Fatalf("jwt auth middleware: %v", err)
	}

	err = authMiddleware.MiddlewareInit()
	if err != nil {
		log.Fatalf("authMiddleware.MiddlewareInit: %v", err)
	}

	apiV1.GET("/twitter/callback", TwitterCallBackHandler)
	apiV1.GET("/discord/callback", DiscordCallBackHandler)
	apiV1.POST("/brows_official_website/callback", BrowsOfficialWebsiteCallback)

	apiV1.GET("/kol_referral_list", GetUserCreditsHandler)
	apiV1.GET("/credits/list", creditsListHandler)

	user := apiV1.Group("/user")
	user.GET("/login_before", GetNonceStringHandler)
	user.POST("/login", authMiddleware.LoginHandler)
	user.GET("/captcha/block", GetBlockCaptcha)
	user.POST("/verify_code", GetNumericVerifyCodeHandler)
	user.POST("/logout", authMiddleware.LogoutHandler)
	user.GET("/refresh_token", authMiddleware.RefreshHandler)

	user.Use(authMiddleware.MiddlewareFunc())
	user.GET("/info", GetUserInfoHandler)
	user.GET("/twitter/auth", TwitterOAuthHandler)
	user.GET("/discord/auth", DiscordOAuthHandler)
	user.POST("/telegram/bind", TelegramBindHandler)
	user.POST("/wallet/bind", BindWalletHandler)

	quest := apiV1.Group("/quest")
	quest.GET("/query_missions", QueryMissionHandler)
	quest.Use(authMiddleware.MiddlewareFunc())
	quest.GET("/query_user_credits", QueryUserCreditsHandler)
	quest.GET("/check", CheckQuestHandler)
	quest.POST("/twitter_link", PostTwitterLinkHandler)
	quest.POST("/kol_referral_code", BindingKOLReferralCodeHandler)
	quest.GET("/official_website/brows", BrowsOfficialWebsite)
	quest.GET("/official_website/verify", VerifyBrowsOfficialWebsite)
	quest.GET("/become_volunteer", GetBecomeVolunteerURL)
	quest.GET("/become_volunteer/verify", VerifyBecomeVolunteer)

	quest.GET("/invite/logs", GetInviteLogs)
	quest.GET("/mission/logs", GetMissionLogs)

	if err := r.Run(cfg.ApiListen); err != nil {
		log.Fatalf("starting server: %v\n", err)
	}
}
