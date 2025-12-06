import Navbar from '../components/Navbar';
import { EventDetails } from '../components/EventDetails';
import SearchBar from '../components/SearchBar';
import { AuthProvider } from '../hooks/useAuth';
import Header from '../components/Header';
import Footer from '../components/Footer';
import HeroSection from '../components/HeroSection';
import { EventCard } from '../components/EventCard';

const Home = () => {
  return (
    <AuthProvider>
      {/* <Navbar /> */}
      <Header />
      <HeroSection />
      {/* <EventDetails /> */}
      <Footer />
    </AuthProvider>
  );
};

export default Home;
