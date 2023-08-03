<template>
  <NavBar title="Profile" />
  <div class="text-center">
    <div class="card" style="width: 20%;">
      <div class="card-body">
        Name: {{ username }} <br>
        Role: {{ role }} <br>
        Email: {{ email }} <br>
      </div>
    </div>
  </div>
</template>

<script>
import NavBar from "@/components/NavBar.vue"
export default {
  name: "ProfileView",
  components: {
    NavBar,
  },
  data() {
    return {
      username: '',
      role: '',
      email: '',
    }
  },
  methods: {},
  beforeMount() {
    // fetch user details from api
    fetch(`http://127.0.0.1:5500/api/register`,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          Authorization: "Bearer " + localStorage.getItem("access_token"),
        },
      }
    ).then(res => res.json())
      .then(data => {
        this.username = data.username
        this.role = data.role
        this.email = data.email
      })
  }
};
</script>
