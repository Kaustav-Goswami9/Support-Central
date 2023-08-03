<template>
    <div class="btn-group dropstart">
        <button class="btn btn-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false"
            data-bs-display="static">
            <i class="bi bi-person-circle"></i>
        </button>
        <ul class="dropdown-menu dropdown-menu-end dropdown-menu-lg-start">
            <li><router-link to="/profile" class="dropdown-item">Profile</router-link></li>
            <li><a class="dropdown-item" href="">My Posts</a></li>
            <li>
                <hr class="dropdown-divider">
            </li>
            <li>
                <a href="" style="color: crimson;" class="dropdown-item" @click="logout">
                    <i class="bi bi-box-arrow-right"></i> Logout
                </a>
            </li>
        </ul>
    </div>
</template>
<script>
import router from "@/router";
export default {
    name: "ProfileIcon",
    data() {
        return {}
    },
    methods: {
        logout() {
            localStorage.clear();
            return router.push("/");
        },
    },
};
</script>
<style scoped></style>