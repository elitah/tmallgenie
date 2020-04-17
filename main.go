package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/elitah/tmallgenie/tmallgenie"

	"github.com/elitah/utils/hash"
	"github.com/elitah/utils/httptools"
	"github.com/elitah/utils/logs"
	"github.com/elitah/utils/random"
	"github.com/elitah/utils/sqlite"
)

func dbCount(db *sqlite.SQLiteDB, tbl_name string, args ...interface{}) (int64, error) {
	//
	if conn, err := db.GetConn(true); nil == err {
		var sql string
		//
		sql = fmt.Sprintf("SELECT COUNT(*) FROM %s", tbl_name)
		//
		if 0 < len(args) {
			if c, ok := args[0].(string); ok {
				sql = fmt.Sprintf("%s WHERE %s", sql, c)
			}
		}
		//
		sql += ";"
		//
		logs.Info(sql)
		//
		if row := conn.QueryRow(sql, args[1:]...); nil != row {
			var cnt int64
			if err := row.Scan(&cnt); nil == err {
				return cnt, nil
			} else {
				return 0, err
			}
		} else {
			return 0, fmt.Errorf("QueryRow return failed")
		}
	} else {
		return 0, err
	}
}

func dbSelectRow(db *sqlite.SQLiteDB, tbl_name, items string, args ...interface{}) error {
	//
	cnt := strings.Count(items, ",")
	//
	if 0 == cnt {
		cnt++
	}
	//
	if cnt <= len(args) {
		if conn, err := db.GetConn(true); nil == err {
			var sql string
			//
			sql = fmt.Sprintf("SELECT %s FROM %s", items, tbl_name)
			//
			if 0 < len(args) {
				if c, ok := args[0].(string); ok {
					sql = fmt.Sprintf("%s WHERE %s", sql, c)
				}
				for i, _ := range args {
					logs.Info("%d: %T", i, args[i])
				}
			}
			//
			sql += ";"
			//

			//
			if 0 == cnt {
				cnt = 1
			}
			//
			logs.Info(sql)
			//
			if row := conn.QueryRow(sql, args[1:len(args)-cnt]...); nil != row {
				return row.Scan(args[len(args)-cnt:]...)
			} else {
				return fmt.Errorf("QueryRow return failed")
			}
		} else {
			return err
		}
	} else {
		return fmt.Errorf("invalid args")
	}
}

func main() {
	var help bool

	var db_path string
	var db_backup, db_step, db_delay int

	var httpaddr string

	var confusion string

	flag.BoolVar(&help, "h", false, "This Help.")

	flag.StringVar(&db_path, "db", "", "database file path.")
	flag.IntVar(&db_backup, "db_backup", 3, "database backup count.")
	flag.IntVar(&db_step, "db_step", 2048, "database backup step.")
	flag.IntVar(&db_delay, "db_delay", 32, "database backup delay.")

	flag.StringVar(&httpaddr, "l", ":80", "http listen address.")

	flag.StringVar(&confusion, "confusion", "", "confusion code.")

	flag.Parse()

	if help || "" == db_path || "" == httpaddr || "" == confusion {
		flag.Usage()
		return
	}

	logs.SetLogger(logs.AdapterConsole, `{"level":99,"color":true}`)
	logs.EnableFuncCallDepth(true)
	logs.SetLogFuncCallDepth(3)
	logs.Async()

	defer logs.Close()

	if db := sqlite.NewSQLiteDB(
		sqlite.WithBackup(db_path, db_backup, db_step, db_delay),
	); nil != db {
		defer db.Close()

		db.CreateTable("oauth", `id INTEGER PRIMARY KEY AUTOINCREMENT,
								client_id TEXT NOT NULL UNIQUE,
								client_secret TEXT NOT NULL,
								option TEXT NOT NULL DEFAULT '',
								timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))`)

		db.CreateTable("oauth_code", `id INTEGER PRIMARY KEY AUTOINCREMENT,
								code TEXT NOT NULL UNIQUE,
								user TEXT NOT NULL,
								timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))`, true)

		db.CreateTable("user", `id INTEGER PRIMARY KEY AUTOINCREMENT,
								username TEXT NOT NULL UNIQUE,
								password TEXT NOT NULL,
								timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))`)

		db.CreateTable("device", `id INTEGER PRIMARY KEY AUTOINCREMENT,
								devid TEXT NOT NULL UNIQUE,
								user TEXT NOT NULL DEFAULT '',
								timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))`)

		db.CreateTable("token", `id INTEGER PRIMARY KEY AUTOINCREMENT,
								access_token TEXT NOT NULL UNIQUE,
								refresh_token TEXT NOT NULL,
								user TEXT NOT NULL,
								timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))`)

		if n, err := db.StartBackup(true); nil == err {
			logs.Warn("表同步完成，同步条数为%d", n)
		} else {
			logs.Error("无法同步: %v", err)
		}

		go func() {
			myhash := hash.New("md5")

			logs.Warn(http.ListenAndServe(httpaddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if resp := httptools.NewHttpHandler(r); nil != resp {
					//
					resp.Debug(true)
					// 释放
					defer func() {
						if o := resp.Output(w); "" != o {
							logs.Info(o)
						}
						resp.Release()
					}()
					// 识别路径
					switch resp.GetPath() {
					case "/":
						return
					case "/oauth2/auth":
						if resp.HttpOnlyIs("GET") {
							//
							redirect_uri := resp.FormValue("redirect_uri")
							client_id := resp.FormValue("client_id")
							response_type := resp.FormValue("response_type")
							state := resp.FormValue("state")
							// 验证参数
							if "" != redirect_uri && "" != client_id && "code" == response_type && "" != state {
								logs.Info("redirect_uri: %s", redirect_uri)
								logs.Info("client_id: %s", client_id)
								logs.Info("state: %s", state)
								// 验证client_id
								if n, err := dbCount(db, "oauth", "client_id==?", client_id); 0 < n {
									//
									if err := resp.TemplateWrite([]byte(`<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<title>认证</title>
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=0">
		<style>
		a {
			margin: 0 5px 0 5px;
			padding: 0;
		}
		p {
			margin: 0;
			padding: 0;
		}
		</style>
	</head>
	<body>
		<form action="/oauth2/confirm" method="post">
			<table>
				<tr>
					<td style="padding-right: 0.5em; text-align: right; width: 40px; font-size: 12px;">用户名</td>
					<td><input type="text" name="username" style="width: 200px;" /></td>
				</tr>
				<tr>
					<td style="padding-right: 0.5em; text-align: right; width: 40px; font-size: 12px;">密码</td>
					<td><input type="password" name="password" style="width: 200px;" /></td>
				</tr>
				<tr>
					<td>
						<input type="hidden" name="redirect_uri" value="{{ .RedirectURI }}" />
						<input type="hidden" name="client_id" value="{{ .ClientID }}" />
						<input type="hidden" name="state" value="{{ .State }}" />
					</td>
					<td></span><input type="submit" value="提交" /></td>
				</tr>
			</table>
		</form>
	</body>
</html>
`), struct {
										RedirectURI string
										ClientID    string
										State       string
									}{
										RedirectURI: redirect_uri,
										ClientID:    client_id,
										State:       state,
									}, "text/html"); nil != err {
										logs.Error("http: %v", err)

										resp.SendHttpCode(http.StatusInternalServerError)
									}
									return
								} else if nil != err {
									logs.Error("no result: %v", err)
								} else {
									logs.Error("empty result")
								}
							} else {
								logs.Error("invalid args")
							}
							//
							resp.SendHttpString("未授权")
							//
							return
						}
						//
						return
					case "/oauth2/confirm":
						if resp.HttpOnlyIs("POST") {
							//
							username := resp.FormValue("username")
							password := resp.FormValue("password")
							redirect_uri := resp.FormValue("redirect_uri")
							client_id := resp.FormValue("client_id")
							state := resp.FormValue("state")
							//
							logs.Info("username: %s", username)
							logs.Info("password: %s", password)
							logs.Info("redirect_uri: %s", redirect_uri)
							logs.Info("client_id: %s", client_id)
							logs.Info("state: %s", state)
							//
							if "" != username && "" != password &&
								"" != redirect_uri && "" != client_id && "" != state {
								//
								myhash.Reset()
								//
								hash.WriteString(myhash, username, password, confusion)
								//
								if n, err := dbCount(
									db,
									"user",
									"username==? AND password==?",
									username,
									hash.SumString(myhash),
								); 0 < n {
									if u, err := url.Parse(redirect_uri); nil == err {
										//
										code := random.NewRandomString(random.ModeNoLine, 32)
										//
										if conn, err := db.GetConn(true); nil == err {
											if _, err := conn.Exec(
												"INSERT OR REPLACE INTO oauth_code (code, user) VALUES (?, ?);",
												code,
												username,
											); nil == err {
												q := u.Query()
												//
												q.Set("code", code)
												q.Set("state", state)
												//
												u.RawQuery = q.Encode()
												//
												resp.SendHttpRedirect(u.String())
												//
												return
											} else {
												logs.Error("db: %v", err)
											}
										} else {
											logs.Error("db: %v", err)
										}
									} else {
										logs.Error("url.Parse: %v", err)
									}
								} else if nil != err {
									logs.Error("no result: %v", err)
								} else {
									logs.Error("empty result")
								}
							} else {
								logs.Error("invalid args")
							}
						}
						//
						resp.SendHttpString("登陆失败")
						//
						return
					case "/oauth2/token":
						if resp.HttpOnlyIs("POST") {
							if err := resp.ParseForm(); nil == err {
								grant_type := resp.FormValue("grant_type")
								client_id := resp.FormValue("client_id")
								client_secret := resp.FormValue("client_secret")
								//
								if "" != grant_type && "" != client_id && "" != client_secret {
									switch grant_type {
									case "authorization_code":
										if code := resp.FormValue("code"); "" != code {
											//
											var username string
											//
											logs.Info("authorization_code => code: %s", code)
											//
											defer func() {
												if conn, err := db.GetConn(true); nil == err {
													conn.Exec(
														"DELETE FROM oauth_code WHERE code==? OR timestamp<=?;",
														code,
														time.Now().Unix()-180,
													)
												}
											}()
											//
											if err := dbSelectRow(db, "oauth_code", "user", "code==? AND timestamp>=?", code, time.Now().Unix()-180, &username); nil == err {
												if "" != username {
													//
													logs.Info("username: %s", username)
													//
													access_token := random.NewRandomString(random.ModeNoLine, 64)
													refresh_token := random.NewRandomString(random.ModeNoLine, 64)
													//
													if conn, err := db.GetConn(true); nil == err {
														if _, err := conn.Exec(
															"INSERT OR REPLACE INTO token (access_token, refresh_token, user) VALUES (?, ?, ?);",
															access_token,
															refresh_token,
															username,
														); nil == err {
															if err = resp.SendJson(struct {
																AccessToken  string `json:"access_token"`
																RefreshToken string `json:"refresh_token"`
																ExpiresIn    int64  `json:"expires_in"`
															}{
																AccessToken:  access_token,
																RefreshToken: refresh_token,
																ExpiresIn:    7200,
															}); nil == err {
																return
															} else {
																logs.Error(err)
															}
														} else {
															logs.Error(err)
														}
													} else {
														logs.Error(err)
													}
												} else {
													logs.Error("no username")
												}
											} else {
												logs.Error(err)
											}
										} else {
											logs.Error("no code")
										}
									case "refresh_token":
										if old_refresh_token := resp.FormValue("refresh_token"); "" != old_refresh_token {
											//
											var username string
											//
											logs.Info("refresh_token: %s", old_refresh_token)
											//
											defer func() {
												if conn, err := db.GetConn(true); nil == err {
													conn.Exec(
														"DELETE FROM token WHERE timestamp<=?;",
														time.Now().Unix()-(7200+1800),
													)
												}
											}()
											//
											if err := dbSelectRow(
												db,
												"token",
												"user",
												"refresh_token==? AND timestamp>=?",
												old_refresh_token,
												time.Now().Unix()-(7200+1800),
												&username,
											); nil == err {
												if "" != username {
													//
													logs.Info("username: %s", username)
													//
													access_token := random.NewRandomString(random.ModeNoLine, 64)
													refresh_token := random.NewRandomString(random.ModeNoLine, 64)
													//
													if conn, err := db.GetConn(true); nil == err {
														if _, err := conn.Exec(
															"UPDATE token SET access_token=?, refresh_token=? WHERE refresh_token==?;",
															access_token,
															refresh_token,
															old_refresh_token,
														); nil == err {
															if err = resp.SendJson(struct {
																AccessToken  string `json:"access_token"`
																RefreshToken string `json:"refresh_token"`
																ExpiresIn    int64  `json:"expires_in"`
															}{
																AccessToken:  access_token,
																RefreshToken: refresh_token,
																ExpiresIn:    7200,
															}); nil == err {
																return
															} else {
																logs.Error(err)
															}
														} else {
															logs.Error(err)
														}
													} else {
														logs.Error(err)
													}
												} else {
													logs.Error("no username")
												}
											} else {
												logs.Error(err)
											}
										} else {
											logs.Error("no refresh_token")
										}
									default:
										logs.Error("invalid grant_type")
									}
								} else {
									logs.Error("invalid args")
								}
							} else {
								logs.Error(": %v", err)
							}
							//
							resp.SendHttpCode(http.StatusBadRequest)
						}
						//
						return
					case "/gw/tmallgenie":
						if resp.HttpOnlyIs("POST") {
							//
							msg := tmallgenie.TMallGenieRequest{}
							//
							if err := resp.GetJson(&msg); nil == err {
								var payload interface{}
								//
								response_name := msg.Header.Name
								//
								logs.Info(msg.GetAccessToken())
								//
								if n, err := dbCount(db, "token", "access_token==?", msg.GetAccessToken()); 0 < n {
									switch msg.Header.Namespace {
									case "AliGenie.Iot.Device.Discovery":
										//
										response_name = "DiscoveryDevicesResponse"
										//
										switch msg.Header.Name {
										case "DiscoveryDevices":
											//
											response := &tmallgenie.TMallGenieResponseDiscovery{}
											// 多孔插座
											if master := tmallgenie.NewTMallGenieResponseDevice("123456", "插座", "outlet", "中国科技有限公司", "智能插座x1"); nil != master {
												//
												master.SetZone("门口")
												master.SetIcon("http://res.cngoldres.com/upload/credit/2016/4/27/a8371bab3b6802dca33200b77d8145ae.jpg")
												master.AddProperties("name", "powerstate")
												master.AddProperties("value", "off")
												master.AddAction("TurnOn")
												master.AddAction("TurnOff")
												master.AddExtensions("extension1", "")
												master.AddExtensions("extension2", "")
												//
												response.Devices = append(response.Devices, master)
												// 插孔1
												if slave := tmallgenie.NewTMallGenieResponseDevice("000000", "插座", "outlet", "中国科技有限公司", "智能插座x1 插孔"); nil != slave {
													//
													slave.SetZone("门口")
													//slave.SetIcon("")
													slave.AddProperties("name", "powerstate")
													slave.AddProperties("value", "off")
													slave.AddAction("TurnOn")
													slave.AddAction("TurnOff")
													slave.AddExtensions("parentId", "123456")
													slave.AddExtensions("extension1", "")
													slave.AddExtensions("extension2", "")
													//
													response.Devices = append(response.Devices, slave)
												}
												// 插孔2
												if slave := tmallgenie.NewTMallGenieResponseDevice("111111", "插座", "outlet", "中国科技有限公司", "智能插座x1 插孔"); nil != slave {
													//
													slave.SetZone("门口")
													//slave.SetIcon()
													slave.AddProperties("name", "powerstate")
													slave.AddProperties("value", "off")
													slave.AddAction("TurnOn")
													slave.AddAction("TurnOff")
													slave.AddExtensions("parentId", "123456")
													slave.AddExtensions("extension1", "")
													slave.AddExtensions("extension2", "")
												}
												// 插孔3
												if slave := tmallgenie.NewTMallGenieResponseDevice("222222", "插座", "outlet", "中国科技有限公司", "智能插座x1 插孔"); nil != slave {
													//
													slave.SetZone("门口")
													//slave.SetIcon()
													slave.AddProperties("name", "powerstate")
													slave.AddProperties("value", "off")
													slave.AddAction("TurnOn")
													slave.AddAction("TurnOff")
													slave.AddExtensions("parentId", "123456")
													slave.AddExtensions("extension1", "")
													slave.AddExtensions("extension2", "")
													//
													response.Devices = append(response.Devices, slave)
												}
											}
											//
											payload = response
										}
									case "AliGenie.Iot.Device.Control":
										switch msg.Header.Name {
										case "TurnOn":
										}
									case "AliGenie.Iot.Device.Query":
										switch msg.Header.Name {
										case "Query":
										}
									}
								} else if nil != err {
									response_name = "ErrorResponse"

									payload = &tmallgenie.TMallGenieResponseError{
										ErrorCode: "SERVICE_ERROR",
										Message:   err.Error(),
									}
								} else {
									response_name = "ErrorResponse"

									payload = &tmallgenie.TMallGenieResponseError{
										ErrorCode: "ACCESS_TOKEN_INVALIDATE",
										Message:   "access_token is invalidate",
									}
								}
								//
								if "" == response_name {
									response_name = "ErrorResponse"

									payload = &tmallgenie.TMallGenieResponseError{
										ErrorCode: "SERVICE_ERROR",
										Message:   "access_token is invalidate",
									}
								}
								//
								resp.SendJson(&tmallgenie.TMallGenieResponse{
									Header: &tmallgenie.TMallGenieHeader{
										Namespace:      msg.Header.Namespace,
										Name:           response_name,
										MessageId:      msg.Header.MessageId,
										PayLoadVersion: msg.Header.PayLoadVersion,
									},
									Payload: payload,
								})
								return
							} else {
								logs.Error(err)
							}
							//
							resp.SendHttpCode(http.StatusBadRequest)
						}
						//
						return
					case "/ctl/tmallgenie":
						logs.Info(resp.URL.Query())
						//
						return
					case "/debug":
						if resp.HttpOnlyIs("GET") {
							switch resp.FormValue("method") {
							case "new_client_id":
								//
								client_id := random.NewRandomString(random.ModeNoLine, 32)
								client_secret := random.NewRandomString(random.ModeNoLine, 64)
								//
								if conn, err := db.GetConn(true); nil == err {
									if _, err := conn.Exec(
										"INSERT OR REPLACE INTO oauth (client_id, client_secret) VALUES (?, ?);",
										client_id,
										client_secret,
									); nil == err {
										resp.SendHttpString(
											fmt.Sprintf(
												"client_id: %s, client_secret: %s",
												client_id,
												client_secret,
											),
										)
										return
									} else {
										logs.Error("db: %v", err)
									}
								} else {
									logs.Error("db: %v", err)
								}
							case "new_username":
								//
								username := random.NewRandomString(random.ModeHexLower, 8)
								password := random.NewRandomString(random.ModeHexLower, 16)
								//
								myhash.Reset()
								//
								hash.WriteString(myhash, username, password, confusion)
								//
								if conn, err := db.GetConn(true); nil == err {
									if _, err := conn.Exec(
										"INSERT OR REPLACE INTO user (username, password) VALUES (?, ?);",
										username,
										hash.SumString(myhash),
									); nil == err {
										resp.SendHttpString(
											fmt.Sprintf(
												"username: %s, password: %s",
												username,
												password,
											),
										)
										return
									} else {
										logs.Error("db: %v", err)
									}
								} else {
									logs.Error("db: %v", err)
								}
							}
							//
							resp.SendHttpString("错误")
							//
							return
						}
						//
						return
					}
					//
					resp.NotFound()
					//
					return
				}
			})))
		}()

		sig := make(chan os.Signal, 1)

		signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

		for {
			select {
			case c := <-sig:
				logs.Warn("Signal: ", c, ", Closing!!!")
				return
			case <-time.After(1 * time.Second):
			}
		}
	}
}
