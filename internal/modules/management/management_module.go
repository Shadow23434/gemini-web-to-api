package management

import "go.uber.org/fx"

var Module = fx.Options(
	fx.Provide(NewManagementService),
	fx.Provide(NewManagementCookieStore),
	fx.Provide(NewManagementController),
	fx.Invoke(RegisterRoutes),
)
