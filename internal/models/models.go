package models

type User struct {
	Id           int    `json:"id,omitempty" bson:"id,omitempty"`
	Login        string `json:"login" bson:"login"`
	Pass         string `json:"pass" bson:"pass,omitempty"`
	RefreshToken string `json:"refresh,omitempty" bson:"refresh,omitempty"`
}
