package utils

import (
	"errors"
	"regexp"
	"unicode"
)

func ValidateLogin(login string) error {
	if len(login) < 8 {
		return errors.New("login must be at least 8 characters long")
	}
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9]+$`, login)
	if !matched {
		return errors.New("login must contain only latin letters and digits")
	}
	return nil
}

func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case !unicode.IsLetter(char) && !unicode.IsDigit(char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower {
		return errors.New("password must contain at least 2 letters in different cases")
	}
	if !hasDigit {
		return errors.New("password must contain at least 1 digit")
	}
	if !hasSpecial {
		return errors.New("password must contain at least 1 special character")
	}

	return nil
}
