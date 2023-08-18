<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

#[Route('/', name: 'security_')]
class SecurityController extends AbstractController
{
    #[Route('/signup', name: 'signup')]
    public function signup(Request $req, EntityManagerInterface $em, UserPasswordHasherInterface $passwordHasher, AuthenticationUtils $authenticationUtils): Response
    {

        $newUser = new User();
        $userForm = $this->createForm(UserType::class, $newUser);
        $userForm->handleRequest($req);

        if ($userForm->isSubmitted() && $userForm->isValid()) {
            $newUser->setPassword($passwordHasher->hashPassword($newUser, $newUser->getPassword()));
            
            
            $em->persist($newUser);
            $em->flush();
            
            $wantConnected = $userForm->get('connected')->getData();

            // if (!$wantConnected) {
                return $this->redirectToRoute('security_login');
            // }
        }

        return $this->render('security/signup.html.twig', [
            'form' => $userForm->createView(),
        ]);
    }

    #[Route('/signin', name: 'signin')]
    public function signin(AuthenticationUtils $authenticationUtils): Response
    {

        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();


        return $this->render('security/login.html.twig', [
            'error' => $error,
            'username' => $lastUsername,
        ]);
    }

    #[Route('/logout', name: 'logout')]
    public function logout() {}
}