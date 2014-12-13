import java.sql.*;
import java.util.ArrayList;
import java.util.Calendar; 

public class DataManager {
	
	private Connection con;

	public DataManager() {
	     try {
	         Class.forName("com.mysql.jdbc.Driver").newInstance();
	     } catch (Exception e) {
	      System.err.println(e.toString());
	     }
	     String url = "jdbc:mysql://isel.cs.unb.ca:3306/cs2043team2A";
		try {
		con = DriverManager.getConnection(url, "cs2043team2A", "cs2043team2A");
		} catch (SQLException e) {
		System.err.println("Database connection error.");
		}
	}
	
	public ArrayList<userObj> getUserList() {
		ArrayList<userObj> userList = new ArrayList<userObj>();
		try {
			Statement st = con.createStatement();
			String sqlQuery = "select * from userTable";
			ResultSet rs = st.executeQuery(sqlQuery);
			while (rs.next()) {
				userObj user = new userObj();
				user.id = rs.getString(1);
				user.hash = rs.getString(2);
				user.isActive = rs.getBoolean(3);
				userList.add(user);
			}
		} catch (SQLException e) {
			System.err.println("SQL error: getUserLost");
		}
		return userList;
	}
	public ArrayList<userObj> getActiveUserList() {
		ArrayList<userObj> userList = new ArrayList<userObj>();
		try {
			Statement st = con.createStatement();
			String sqlQuery = "select * from userTable";
			ResultSet rs = st.executeQuery(sqlQuery);
			while (rs.next()) {
				userObj user = new userObj();
				user.id = rs.getString(1);
				user.hash = rs.getString(2);
				user.isActive = rs.getBoolean(3);
				if(user.isActive == true);
					userList.add(user);
			}
		} catch (SQLException e) {
			System.err.println("SQL error: getActiveUsers");
		}
		return userList;
	}
	public void addUser(userObj user){
		try {
			Statement st = con.createStatement();
			String sqlQuery = "insert into userTable values " +
					"('" + user.id + "','" + user.hash + "','" +
					user.isActive + "')";
			System.out.println(sqlQuery);
			st.executeUpdate(sqlQuery);
			} catch (SQLException e) {
				System.err.println("SQL error: addUser");
			}
	}
	public void removeUser(userObj user){
		try {
			Statement st = con.createStatement();
			String sqlQuery = "delete from userTable values " +
					"('" + user.id + "','" + user.hash + "','" +
					user.isActive + "')";
			System.out.println(sqlQuery);
			st.executeUpdate(sqlQuery);
			} catch (SQLException e) {
				System.err.println("SQL error: removeUser");
			}
	}
}
