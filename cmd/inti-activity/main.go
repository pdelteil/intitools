package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	intitools "github.com/0xJeti/intitools/pkg/intigo"
	"golang.org/x/time/rate"
)

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	conf := &config{}

	// Create channel for accepting signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	defer func() {
		cancel()
	}()

	go func() {
		for {
			select {
			case s := <-signalChan:
				switch s {
				case syscall.SIGHUP:
					conf.init(os.Args)
				case os.Interrupt:
					cancel()
					os.Exit(1)
				}
			case <-ctx.Done():
				log.Printf("Done.")
				os.Exit(1)
			}
		}
	}()

	if err := run(ctx, conf, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, conf *config, out io.Writer) error {
	conf.init(os.Args)

	rl := rate.NewLimiter(rate.Every(time.Second), 2) // 2 requests every second
	c := intitools.NewClient(conf.username, conf.password, conf.secret, rl, conf.proxy)
	c.WebhookURL = conf.webhookurl

	sendlast := conf.sendlast

	log.SetOutput(os.Stdout)

	log.Printf("Starting monitoring with tick %s!!", conf.tick)

	// Send the message to the Discord webhook
	//activity := intitools.Activity{Programid:       "abc123",Submissioncode:  "def456",		Programname:     "Test Program",		Submissiontitle: "Test Submission", Companyhandle:   "test-company",		Programhandle:   "test-program",		Programlogoid:   "123456",		Discriminator:   1,}
    //message := c.DiscordFormatActivity(activity)

	//if err := c.DiscordSend(ctx, message); 
    //err != nil {  log.Println("error", err) return nil	}
	httpctx := context.Background()
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-time.Tick(conf.tick):
            log.Printf("Starting authentication")
			err := c.Authenticate()
			if err != nil {
				log.Printf("Authentication error!: %s\n", err)
				return err//continue

			}
            //only login
            return nil
			numActivities, err := c.CheckActivity(httpctx)
			if err != nil {
				log.Printf("CheckActivity error: %s\n", err)
				continue
			}

			// Use sendlast for first iteration and reset for all other
			numActivities += sendlast
			sendlast = 0

			if numActivities == 0 {
				continue
			}

			res, err := c.GetActivities(httpctx)

			if err != nil {
				log.Printf("GetActivities error: %s\n", err)
				continue
			}

			for idx, activity := range res.Activities {
				if idx > numActivities-1 {
					break
				}

				if conf.webhooktype == "slack" {
					message := c.SlackFormatActivity(activity)
					err = c.SlackSend(message)
				} else {
					message := c.DiscordFormatActivity(activity)
					err = c.DiscordSend(httpctx, message)
				}

				if err != nil {
					log.Printf("Webhook send error: %s\n", err)
					continue
				}

			}

			c.LastViewed = time.Now().Unix()
		}
	}

}
