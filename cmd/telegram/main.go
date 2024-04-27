package main

import (
	"github.com/gnasnik/titan-quest/config"
	"github.com/gnasnik/titan-quest/core/bot/telegram"
	"github.com/gnasnik/titan-quest/core/dao"
	"github.com/spf13/viper"
	"log"
	"os"
	"os/signal"
)

func main() {
	viper.AddConfigPath(".")
	viper.SetConfigName("config")
	viper.SetConfigType("toml")
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("reading config file: %v\n", err)
	}

	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("unmarshaling config file: %v\n", err)
	}

	if err := dao.Init(&cfg); err != nil {
		log.Fatalf("initital: %v\n", err)
	}

	//ctx := context.Background()

	go telegram.RunTelegramBot(cfg.TelegramBotToken, cfg.OfficialTelegramGroupId)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	log.Println("Gracefully shutting down")

	//log.Println("Success")
}
