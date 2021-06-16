package main

import (
	"github.com/gxravel/auth/internal/api/handler"
	"github.com/gxravel/auth/internal/conf"
	"github.com/gxravel/auth/internal/db"
	"github.com/gxravel/auth/internal/model/user"
	"github.com/gxravel/auth/pkg/jwt"
	"go.uber.org/fx"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	fx.New(
		fx.Provide(
			conf.New,
			conf.NewJWT,
			handler.NewLogger,
			handler.NewRedis,
			db.New,
			user.New,
			jwt.New,
			func(w *user.Wrapper) user.Manager { return w },
			func(e *jwt.Environment) jwt.Manager { return e },
			handler.NewEnvironment,
			handler.NewServer,
		),
		fx.Invoke(
			handler.Register,
		),
	).Run()

	// done := make(chan os.Signal, 1)
	// signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// env.log.Print("server started")

	// <-done

	// env.log.Print("server stopped")

	// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// defer func() {
	// 	db.Close()
	// 	redis.Close()
	// 	cancel()
	// }()

	// if err := srv.Shutdown(ctx); err != nil {
	// 	env.log.Fatalf("server shutdown failed: %+v", err)
	// }
	// env.log.Print("server exited properly")
}
