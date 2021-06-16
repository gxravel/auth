package conf_test

import (
	"reflect"
	"testing"

	. "github.com/gxravel/auth/internal/conf"
)

func testIfFieldEmpty(t *testing.T, data interface{}) {
	v := reflect.ValueOf(data).Elem()
	vType := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Errorf("the field %s is empty", vType.Field(i).Name)
		}
	}
}

func TestNew(t *testing.T) {
	config := New()
	testIfFieldEmpty(t, config)
}

func TestNewJWT(t *testing.T) {
	config := NewJWT()
	testIfFieldEmpty(t, config)
}

// func TestGetProd(t *testing.T) {
// 	os.Setenv("ENV", "production")
// 	config := Get()
// 	testIfFieldEmpty(t, config)
// }

// func TestGetJWTProd(t *testing.T) {
// 	config := GetJWT()
// 	testIfFieldEmpty(t, config)
// }
