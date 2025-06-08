package models

type Video struct {
	Title string `bson:"title"`
	Creat string `bson:"created_at"`
	Type  string `bson:"type"`
	Wtf   string `bson:"wtf"`
}

type User struct {
	Id           int    `json:"id,omitempty" bson:"id,omitempty"`
	Login        string `json:"login" bson:"login"`
	Pass         string `json:"pass" bson:"pass,omitempty"`
	RefreshToken string `json:"refresh,omitempty" bson:"refresh,omitempty"`
}

type Tokens struct {
	Token []string `json:"tokens"`
}

type Token struct {
	Token string `json:"token"`
}
